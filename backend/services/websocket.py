"""实时事件推送服务 — 基于 Flask SSE (Server-Sent Events)，无需额外依赖"""
import json
import time
from threading import Lock
from datetime import datetime, timezone

from flask import Response, stream_with_context

_listeners: dict = {}
_listener_lock = Lock()
_counter = 0


def add_listener(conn_id: str):
    with _listener_lock:
        _listeners[conn_id] = []


def remove_listener(conn_id: str):
    with _listener_lock:
        _listeners.pop(conn_id, None)


def _safe_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, default=str)


def _broadcast(event: dict):
    global _counter
    _counter += 1
    msg = f"id: {_counter}\ndata: {_safe_json(event)}\n\n"
    with _listener_lock:
        for conn_id in list(_listeners.keys()):
            _listeners[conn_id].append(msg)
        for conn_id in _listeners:
            if len(_listeners[conn_id]) > 50:
                _listeners[conn_id] = _listeners[conn_id][-50:]


def broadcast_event(event_type: str, data: dict):
    _broadcast({
        "type": event_type,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def events_stream():
    global _counter
    _counter += 1
    conn_id = f"{_counter}-{int(time.time() * 1000)}"
    add_listener(conn_id)

    def generate():
        try:
            heartbeat = f"id: h{_counter}\nevent: heartbeat\ndata: {json.dumps({'type': 'connected', 'conn_id': conn_id})}\n\n"
            yield heartbeat

            while True:
                time.sleep(0.5)
                with _listener_lock:
                    queue = _listeners.get(conn_id, [])
                    _listeners[conn_id] = []

                for msg in queue:
                    yield msg

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
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


def broadcast_detection(text: str, is_malicious: bool, reason: str,
                        threat_level: str, confidence: int,
                        source_ip: str = None, category: str = None):
    broadcast_event("detection", {
        "text_preview": text[:80],
        "is_malicious": is_malicious,
        "reason": reason,
        "threat_level": threat_level,
        "confidence": confidence,
        "source_ip": source_ip,
        "category": category,
    })


def broadcast_alert(event_type: str, detail: str, status: str,
                    threat_level: str, confidence: int,
                    source_ip: str = None, action: str = None,
                    tool_name: str = None, target: str = None,
                    rule_id: str = None, category: str = None,
                    metadata: dict = None):
    payload = {
        "type": event_type,
        "detail": detail,
        "status": status,
        "threat_level": threat_level,
        "confidence": confidence,
        "source_ip": source_ip,
        "action": action,
        "tool_name": tool_name,
        "target": target,
        "rule_id": rule_id,
        "category": category,
        "metadata": metadata or {},
    }
    _broadcast({
        "type": "alert",
        "data": payload,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    # 同时触发外部 webhook 通知（异步，不阻塞推送）
    try:
        from services.webhook_notifier import fire_webhooks
        fire_webhooks(
            event_type=payload["type"],
            detail=payload.get("detail", ""),
            status=payload.get("status", ""),
            threat_level=payload.get("threat_level", ""),
            confidence=payload.get("confidence", 0),
            source_ip=payload.get("source_ip"),
            action=payload.get("action"),
            tool_name=payload.get("tool_name"),
            target=payload.get("target"),
            rule_id=payload.get("rule_id"),
            category=payload.get("category"),
            metadata=payload.get("metadata"),
        )
    except Exception:
        pass
        pass
