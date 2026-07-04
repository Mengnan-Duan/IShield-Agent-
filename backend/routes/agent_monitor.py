"""Agent 监控 API — Phase 2.1 新增"""
from flask import Blueprint, jsonify, request

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response, make_error, Err
from middleware.error_handler import ValidationError
from tools.openclaw_adapter import (
    AgentMonitor,
    get_agent_stats,
    create_openclaw_proxy,
    _registered_agents,
)

agent_bp = Blueprint("agent", __name__, url_prefix="/api/agent")


@agent_bp.route("/register", methods=["POST"])
def register_agent():
    """注册一个新的 Agent 监控实例"""
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        raise ValidationError("agent_id 不能为空")

    agent_name = data.get("agent_name", f"Agent-{agent_id}")
    system_prompt = data.get("system_prompt", "")

    if agent_id in _registered_agents:
        return make_response({"registered": True, "agent_id": agent_id, "message": "Agent 已存在"})

    monitor = AgentMonitor(
        agent_id=agent_id,
        agent_name=agent_name,
        system_prompt=system_prompt,
    )
    return make_response({"registered": True, "agent_id": agent_id, "agent_name": agent_name})


@agent_bp.route("/unregister", methods=["POST"])
def unregister_agent():
    """注销 Agent"""
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        raise ValidationError("agent_id 不能为空")

    from tools.openclaw_adapter import _agents_lock
    with _agents_lock:
        if agent_id in _registered_agents:
            del _registered_agents[agent_id]
            return make_response({"unregistered": True, "agent_id": agent_id})
    return make_error(Err.NOT_FOUND, f"Agent {agent_id} 未找到")


@agent_bp.route("/stats", methods=["GET"])
def get_agents_stats():
    """获取所有或指定 Agent 的统计信息"""
    agent_id = request.args.get("agent_id")
    stats = get_agent_stats(agent_id)
    return make_response(stats)


@agent_bp.route("/execute", methods=["POST"])
def execute_tool():
    """通过 Agent 监控执行工具调用"""
    data = request.get_json(silent=True)
    if not data:
        raise ValidationError("无效的 JSON body")

    agent_id = data.get("agent_id", "default")
    tool_name = data.get("tool")
    params = data.get("params", {})
    user_message = data.get("message", "")

    if not tool_name:
        raise ValidationError("tool 不能为空")

    from tools.openclaw_adapter import _agents_lock
    with _agents_lock:
        monitor = _registered_agents.get(agent_id)

    if not monitor:
        monitor = AgentMonitor(agent_id=agent_id, agent_name=f"Agent-{agent_id}")

    result = monitor.execute_tool(tool_name, params, user_message, chain_id=data.get("chain_id"))
    return make_response(result, chain_id=result.get("chain_id"))


@agent_bp.route("/calls", methods=["GET"])
def get_agent_calls():
    """获取 Agent 的调用历史"""
    agent_id = request.args.get("agent_id")
    raw_limit = request.args.get("limit", "50")
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        raise ValidationError("limit 必须是整数")
    limit = max(1, min(limit, 200))

    from tools.openclaw_adapter import _agents_lock
    with _agents_lock:
        if agent_id:
            monitor = _registered_agents.get(agent_id)
            if not monitor:
                return make_response({"calls": [], "total": 0})
            calls = monitor.get_recent_calls(limit)
            return make_response({"calls": calls, "total": monitor.request_count, "blocked": monitor.blocked_count})

        calls = []
        total = 0
        blocked = 0
        for monitor in _registered_agents.values():
            recent = monitor.get_recent_calls(limit)
            calls.extend(recent)
            total += monitor.request_count
            blocked += monitor.blocked_count

    calls.sort(key=lambda c: str(c.get("timestamp", "")), reverse=True)
    return make_response({"calls": calls[:limit], "total": total, "blocked": blocked})


@agent_bp.route("/list", methods=["GET"])
def list_agents():
    """列出所有已注册的 Agent"""
    from tools.openclaw_adapter import _agents_lock
    with _agents_lock:
        agents = [
            {"agent_id": aid, "agent_name": m.agent_name, "enabled": m.enabled}
            for aid, m in _registered_agents.items()
        ]
    return make_response({"agents": agents, "count": len(agents)})


@agent_bp.route("/summary", methods=["GET"])
def agent_summary():
    """Agent 全局汇总 — 从 events 表聚合 agent_tool_call 类型。

    返回:
        {
          "total_calls": int,
          "blocked_count": int,
          "confirmed_count": int,
          "allowed_count": int,
          "block_rate": float,
          "avg_duration_ms": float,
          "tool_distribution": {tool_name: count},
          "agent_distribution": {agent_name: count},
          "active_agents": int,
        }
    """
    from services.events import get_events_from_db

    try:
        rows = get_events_from_db(
            limit=1000,
            offset=0,
            type_filter="agent_tool_call",
        )
    except Exception:
        rows = []

    total = len(rows)
    blocked = sum(1 for r in rows if r.get("status") == "已阻断")
    confirmed = sum(1 for r in rows if r.get("status") == "待确认")
    allowed = sum(1 for r in rows if r.get("status") == "已放行")
    block_rate = round(blocked / max(total, 1) * 100, 1)

    # 工具分布
    tool_dist: dict = {}
    agent_dist: dict = {}
    durations = []
    for r in rows:
        tool = r.get("tool_name") or "unknown"
        tool_dist[tool] = tool_dist.get(tool, 0) + 1
        meta = r.get("metadata") or {}
        agent_name = meta.get("agent_name") or "unknown"
        agent_dist[agent_name] = agent_dist.get(agent_name, 0) + 1
        d = meta.get("duration_ms")
        if isinstance(d, (int, float)):
            durations.append(int(d))

    avg_duration = round(sum(durations) / max(len(durations), 1), 1) if durations else 0.0
    active_agents = sum(1 for aid, m in _registered_agents.items() if m.enabled)

    return make_response({
        "total_calls": total,
        "blocked_count": blocked,
        "confirmed_count": confirmed,
        "allowed_count": allowed,
        "block_rate": block_rate,
        "avg_duration_ms": avg_duration,
        "tool_distribution": dict(sorted(tool_dist.items(), key=lambda x: -x[1])[:10]),
        "agent_distribution": dict(sorted(agent_dist.items(), key=lambda x: -x[1])[:10]),
        "active_agents": active_agents,
        "recent_calls_sample": rows[:5],  # 最近 5 条样本
    })
