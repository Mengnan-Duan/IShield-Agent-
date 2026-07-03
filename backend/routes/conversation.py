"""多轮对话攻击模拟路由"""
from flask import Blueprint, request

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.events import add_event
from services.conversation_guard import create_session, append_turns, evaluate_session

conversation_bp = Blueprint("conversation", __name__, url_prefix="/api/conversation")


def _as_bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "fast"}:
            return True
        if normalized in {"0", "false", "no", "off", "precise"}:
            return False
    return bool(value)


@conversation_bp.route("/session", methods=["POST"])
def create_conversation_session():
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")
    data = request.get_json(silent=True) or {}
    turns = data.get("turns", [])
    session = create_session(turns)
    evaluation = evaluate_session(session["turns"])
    session_id = session["session_id"]

    add_event(
        event_type="对话会话",
        detail=f"创建会话，轮数={len(session['turns'])}",
        status="已创建",
        action="conversation_session",
        tool_name="conversation_guard",
        target=session_id,
        category="conversation_simulation",
        threat_level=evaluation.get("risk_level"),
        confidence=evaluation.get("cumulative_risk", 0),
        chain_id=session_id,
        stage="conversation_created",
        metadata={"summary": session.get("summary")},
    )

    return make_response({
        "session_id": session_id,
        "turns": session["turns"],
        "summary": session["summary"],
        "evaluation": evaluation,
    })


@conversation_bp.route("/evaluate", methods=["POST"])
def evaluate_conversation():
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    existing_turns = data.get("existing_turns", [])
    new_turns = data.get("new_turns", data.get("turns", []))
    session_id = data.get("session_id") or data.get("chain_id")
    fast = _as_bool(data.get("fast"), True)

    combined = append_turns(existing_turns, new_turns)
    evaluation = evaluate_session(combined["turns"], fast=fast)

    chain_id = session_id or f"conv-anon-{len(combined['turns'])}"
    add_event(
        event_type="多轮对话评估",
        detail=f"会话={chain_id}, 轮数={evaluation.get('turn_count', 0)}, 状态={evaluation.get('status')}",
        status="已评估" if evaluation.get("status") == "safe" else "已告警",
        action="conversation_evaluate",
        tool_name="conversation_guard",
        target=chain_id,
        category="conversation_simulation",
        threat_level=evaluation.get("risk_level"),
        confidence=evaluation.get("cumulative_risk", 0),
        chain_id=chain_id,
        stage="conversation_evaluated",
        metadata={
            "alerts": evaluation.get("alerts", []),
            "summary": evaluation.get("summary", {}),
            "engine": evaluation.get("engine"),
            "elapsed_ms": evaluation.get("elapsed_ms"),
        },
    )

    return make_response({
        "session_id": chain_id,
        "turns": combined["turns"],
        "summary": combined["summary"],
        "evaluation": evaluation,
    })
