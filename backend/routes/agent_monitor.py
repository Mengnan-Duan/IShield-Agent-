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

    result = monitor.execute_tool(tool_name, params, user_message)
    return make_response(result)


@agent_bp.route("/calls", methods=["GET"])
def get_agent_calls():
    """获取 Agent 的调用历史"""
    agent_id = request.args.get("agent_id")
    limit = int(request.args.get("limit", 50))

    from tools.openclaw_adapter import _agents_lock
    with _agents_lock:
        monitor = _registered_agents.get(agent_id) if agent_id else None

    if not monitor:
        return make_response({"calls": [], "total": 0})

    calls = monitor.get_recent_calls(limit)
    return make_response({"calls": calls, "total": monitor.request_count, "blocked": monitor.blocked_count})


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
