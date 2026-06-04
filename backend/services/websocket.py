"""实时事件推送服务 — 基于 Flask SSE (Server-Sent Events)，无需额外依赖"""
import json
import time
from threading import Thread, Lock
from datetime import datetime, timezone
from collections import defaultdict
from functools import wraps

from flask import Response, request, stream_with_context

# 全局事件队列（按连接 ID 分发）
_listeners: dict = {}           # connection_id -> queue (list)
_listener_lock = Lock()
_counter = 0


# ── 连接管理 ────────────────────────────────────────────────────────────────────
def add_listener(conn_id: str):
    with _listener_lock:
        _listeners[conn_id] = []


def remove_listener(conn_id: str):
    with _listener_lock:
        _listeners.pop(conn_id, None)


def _safe_json(data: dict) -> str:
    """序列化 dict 为 JSON 字符串，跳过不可序列化的字段"""
    return json.dumps(data, ensure_ascii=False, default=str)


def _broadcast(event: dict):
    """将事件广播给所有监听中的连接"""
    global _counter
    _counter += 1
    msg = f"id: {_counter}\ndata: {_safe_json(event)}\n\n"
    with _listener_lock:
        for conn_id in list(_listeners.keys()):
            _listeners[conn_id].append(msg)
        # 限制每个连接最多积压 50 条
        for conn_id in _listeners:
            if len(_listeners[conn_id]) > 50:
                _listeners[conn_id] = _listeners[conn_id][-50:]


# ── 公开广播 API（供其他 services 调用）─────────────────────────────────────────
def broadcast_event(event_type: str, data: dict):
    """
    任何 service 调用此函数即可广播一个实时事件。
    示例：
        from services.websocket import broadcast_event
        broadcast_event("new_event", {"type": "检测", "status": "已拦截", ...})
    """
    _broadcast({
        "type": event_type,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── SSE 端点 ───────────────────────────────────────────────────────────────────
def events_stream():
    """
    GET /api/events/stream
    Flask SSE 端点，客户端 EventSource 持续监听。
    每次请求分配唯一 connection_id，连接断开时自动清理。
    """
    global _counter
    _counter += 1
    conn_id = f"{_counter}-{int(time.time() * 1000)}"
    add_listener(conn_id)

    def generate():
        try:
            # 发送心跳保持连接活跃（每 25 秒一条）
            heartbeat = f"id: h{_counter}\nevent: heartbeat\ndata: {json.dumps({'type': 'connected', 'conn_id': conn_id})}\n\n"
            yield heartbeat

            while True:
                time.sleep(0.5)  # 每 0.5s 检查一次队列
                with _listener_lock:
                    queue = _listeners.get(conn_id, [])
                    _listeners[conn_id] = []

                for msg in queue:
                    yield msg

                # 心跳
                hb = f"id: h{int(time.time() * 1000)}\nevent: ping\ndata: {{\"time\": \"{datetime.now(timezone.utc).isoformat()}\"}}\n\n"
                yield hb

        except GeneratorExit:
            pass
        finally:
            remove_listener(conn_id)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",    # 禁用 Nginx 缓冲
            "Access-Control-Allow-Origin": "*",
        },
    )


# ── 便捷广播函数（直接挂载到 services 层）───────────────────────────────────────
def broadcast_detection(text: str, is_malicious: bool, reason: str,
                        threat_level: str, confidence: int):
    """检测完成时广播，便于前端实时更新事件列表"""
    broadcast_event("detection", {
        "text_preview": text[:80],
        "is_malicious": is_malicious,
        "reason": reason,
        "threat_level": threat_level,
        "confidence": confidence,
    })


def broadcast_alert(event_type: str, detail: str, status: str,
                    threat_level: str, confidence: int):
    """拦截告警时广播"""
    broadcast_event("alert", {
        "type": event_type,
        "detail": detail,
        "status": status,
        "threat_level": threat_level,
        "confidence": confidence,
    })
