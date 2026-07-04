"""IShield v6.0 external Agent runtime protocol service."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List, Tuple

from services.events import add_event, get_events_from_db
from services.policy import Action, get_policy_engine, serialize_policy_result
from services.runtime_gateway import execute_runtime_request


PROTOCOL_VERSION = "v6.0"
DEFAULT_AGENT_ID = "external-agent"
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_SESSION_LOCK = Lock()


STEP_TOOL_ALIASES = {
    "tool": "tool_call",
    "tool_call": "tool_call",
    "function_call": "tool_call",
    "memory": "memory_write",
    "memory_write": "memory_write",
    "memory_read": "memory_read",
    "rag": "rag_query",
    "rag_query": "rag_query",
    "retrieve": "rag_query",
    "delegation": "delegation",
    "delegate": "delegation",
    "output": "output",
    "message": "output",
}


def sdk_config(base_url: str = "") -> Dict[str, Any]:
    base = (base_url or "http://127.0.0.1:5000").rstrip("/")
    return {
        "version": PROTOCOL_VERSION,
        "product": "IShield Agent Runtime Protocol",
        "base_url": base,
        "endpoints": {
            "ingest": f"{base}/api/runtime/ingest",
            "decision": f"{base}/api/runtime/decision",
            "sessions": f"{base}/api/runtime/sessions",
            "sdk_config": f"{base}/api/runtime/sdk-config",
        },
        "required_fields": ["agent_id", "session_id", "step_type"],
        "decision_fields": ["agent_id", "session_id", "tool_name", "tool_args"],
        "supported_steps": [
            "tool_call",
            "memory_read",
            "memory_write",
            "rag_query",
            "delegation",
            "output",
        ],
        "python_example": (
            "from ishield_client import IShieldClient\n"
            "guard = IShieldClient('http://127.0.0.1:5000')\n"
            "decision = guard.guard_tool_call('read_file', {'path': '../config/.env'})\n"
            "if decision['decision'] == 'blocked':\n"
            "    raise RuntimeError(decision['reason'])"
        ),
    }


def ingest_step(payload: Dict[str, Any], source_ip: str = None, trace_id: str = None) -> Dict[str, Any]:
    normalized = normalize_payload(payload)
    agent_id = normalized["agent_id"]
    session_id = normalized["session_id"]
    chain_id = normalized["chain_id"]
    step_type = normalized["step_type"]
    action, params = protocol_action_and_params(normalized)
    policy_result = evaluate_protocol_policy(action, params)
    decision = policy_result.action.value
    status = _status_from_decision(decision, ingest=True)
    severity = int(getattr(policy_result, "severity", 0) or 0)
    metadata = {
        "protocol_version": PROTOCOL_VERSION,
        "agent_id": agent_id,
        "agent_name": normalized.get("agent_name"),
        "session_id": session_id,
        "step_id": normalized["step_id"],
        "step_type": step_type,
        "tool_name": normalized.get("tool_name"),
        "tool_args": normalized.get("tool_args"),
        "memory": normalized.get("memory"),
        "rag": normalized.get("rag"),
        "delegation": normalized.get("delegation"),
        "output": normalized.get("output"),
        "decision": decision,
        "policy_trace": serialize_policy_result(policy_result),
        "trace_id": trace_id,
        "status_code": "blocked" if decision == "block" else ("confirm" if decision == "confirm" else "review"),
    }
    event_id = add_event(
        event_type="Agent 接入步骤",
        detail=_protocol_detail(normalized, action, params),
        status=status,
        source_ip=source_ip or normalized.get("source_ip") or "127.0.0.1",
        action=action,
        tool_name=action,
        target=_target_from_params(params),
        rule_id=policy_result.triggered_rule,
        category="runtime_protocol",
        threat_level=_threat_from_decision(decision, severity),
        confidence=severity,
        chain_id=chain_id,
        stage=f"runtime_{step_type}",
        metadata=metadata,
    )
    session = _touch_session(
        agent_id=agent_id,
        agent_name=normalized.get("agent_name"),
        session_id=session_id,
        chain_id=chain_id,
        source_ip=source_ip or normalized.get("source_ip"),
        last_step_type=step_type,
        last_decision=decision,
        event_id=event_id,
        tool_name=action,
    )
    return {
        "version": PROTOCOL_VERSION,
        "accepted": True,
        "event_id": event_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "chain_id": chain_id,
        "step_id": normalized["step_id"],
        "step_type": step_type,
        "decision": decision,
        "rule_id": policy_result.triggered_rule,
        "severity": severity,
        "session": session,
    }


def decide_step(payload: Dict[str, Any], source_ip: str = None, trace_id: str = None, token_meta: dict = None) -> Dict[str, Any]:
    normalized = normalize_payload(payload)
    action, params = protocol_action_and_params(normalized)
    if not action:
        action = "agent_message"
    started = time.perf_counter()
    runtime = execute_runtime_request(
        action=action,
        params=params,
        chain_id=normalized["chain_id"],
        source_ip=source_ip or normalized.get("source_ip") or "127.0.0.1",
        token_meta=token_meta,
        trace_id=trace_id,
        actor=normalized["agent_id"],
        fast_detection=bool(payload.get("fast_detection", True)),
        user_input="" if normalized.get("step_type") == "tool_call" else (normalized.get("input") or normalized.get("output") or ""),
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    decision = _normalize_decision(runtime.get("decision") or runtime.get("result"))
    _touch_session(
        agent_id=normalized["agent_id"],
        agent_name=normalized.get("agent_name"),
        session_id=normalized["session_id"],
        chain_id=runtime.get("chain_id") or normalized["chain_id"],
        source_ip=source_ip or normalized.get("source_ip"),
        last_step_type=normalized["step_type"],
        last_decision=decision,
        event_id=None,
        tool_name=action,
        risk_score=runtime.get("risk_score"),
    )
    return {
        "version": PROTOCOL_VERSION,
        "agent_id": normalized["agent_id"],
        "session_id": normalized["session_id"],
        "chain_id": runtime.get("chain_id") or normalized["chain_id"],
        "step_id": normalized["step_id"],
        "step_type": normalized["step_type"],
        "tool_name": action,
        "decision": decision,
        "status_code": runtime.get("status_code") or decision,
        "runtime_conclusion": runtime.get("runtime_conclusion") or runtime.get("reason") or runtime.get("message") or "",
        "blocked": decision == "blocked",
        "blocked_at": runtime.get("blocked_at"),
        "rule_id": runtime.get("rule_id") or _rule_from_steps(runtime.get("steps") or []),
        "reason": runtime.get("reason") or runtime.get("message") or "",
        "risk_score": runtime.get("risk_score") or 0,
        "risk_level": runtime.get("risk_level") or "none",
        "elapsed_ms": elapsed_ms,
        "runtime": runtime,
    }


def list_sessions(limit: int = 50) -> Dict[str, Any]:
    limit = _clamp_int(limit, 50, 1, 200)
    with _SESSION_LOCK:
        sessions = list(_SESSIONS.values())
    sessions.sort(key=lambda item: str(item.get("last_seen") or ""), reverse=True)
    recent_events = get_events_from_db(limit=120)
    external_events = [
        item for item in recent_events
        if ((item.get("metadata") or {}).get("protocol_version") == PROTOCOL_VERSION)
        or str(item.get("category") or "") == "runtime_protocol"
    ]
    if external_events:
        seen = {item["session_id"] for item in sessions if item.get("session_id")}
        for event in external_events:
            meta = event.get("metadata") or {}
            sid = meta.get("session_id")
            if not sid or sid in seen:
                continue
            seen.add(sid)
            sessions.append({
                "agent_id": meta.get("agent_id") or DEFAULT_AGENT_ID,
                "agent_name": meta.get("agent_name") or meta.get("agent_id") or DEFAULT_AGENT_ID,
                "session_id": sid,
                "chain_id": event.get("chain_id"),
                "source_ip": event.get("source_ip"),
                "created_at": event.get("time"),
                "last_seen": event.get("time"),
                "last_step_type": meta.get("step_type") or event.get("stage"),
                "last_decision": meta.get("decision") or event.get("status_code"),
                "last_tool": event.get("tool_name") or event.get("action"),
                "event_count": 1,
                "risk_score": event.get("confidence") or 0,
            })
    sessions = sessions[:limit]
    blocked = sum(1 for item in sessions if str(item.get("last_decision") or "").lower() in {"blocked", "block"})
    return {
        "version": PROTOCOL_VERSION,
        "count": len(sessions),
        "blocked_sessions": blocked,
        "sessions": sessions,
        "recent_events": [_event_brief(item) for item in external_events[:20]],
    }


def normalize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        payload = {}
    agent_id = _clean(payload.get("agent_id") or payload.get("agent") or DEFAULT_AGENT_ID)
    session_id = _clean(payload.get("session_id") or payload.get("conversation_id") or f"sess-{uuid.uuid4().hex[:10]}")
    chain_id = _clean(payload.get("chain_id") or f"chain-{session_id}")
    raw_step_type = _clean(payload.get("step_type") or payload.get("type") or payload.get("event") or "tool_call")
    step_type = STEP_TOOL_ALIASES.get(raw_step_type.lower(), raw_step_type.lower())
    tool_args = payload.get("tool_args", payload.get("args", payload.get("params", {})))
    return {
        "agent_id": agent_id,
        "agent_name": _clean(payload.get("agent_name") or payload.get("name") or agent_id),
        "session_id": session_id,
        "chain_id": chain_id,
        "step_id": _clean(payload.get("step_id") or payload.get("id") or f"step-{uuid.uuid4().hex[:10]}"),
        "step_type": step_type,
        "tool_name": _clean(payload.get("tool_name") or payload.get("tool") or payload.get("action") or ""),
        "tool_args": tool_args if isinstance(tool_args, (dict, list, str)) else str(tool_args),
        "input": _clean(payload.get("input") or payload.get("prompt") or payload.get("message") or ""),
        "memory": payload.get("memory") or {},
        "rag": payload.get("rag") or {},
        "delegation": payload.get("delegation") or {},
        "output": payload.get("output") or payload.get("response") or "",
        "source_ip": _clean(payload.get("source_ip") or ""),
    }


def protocol_action_and_params(normalized: Dict[str, Any]) -> Tuple[str, Any]:
    step_type = normalized.get("step_type")
    if step_type == "tool_call":
        return normalized.get("tool_name") or "agent_message", normalized.get("tool_args") or {}
    if step_type in {"memory_read", "memory_write"}:
        memory = normalized.get("memory") or {}
        if not memory and normalized.get("tool_args"):
            memory = normalized.get("tool_args")
        return step_type, memory
    if step_type == "rag_query":
        rag = normalized.get("rag") or normalized.get("tool_args") or {}
        return "rag_search", rag
    if step_type == "delegation":
        delegation = normalized.get("delegation") or normalized.get("tool_args") or {}
        return "agent_delegate", delegation
    if step_type == "output":
        return "agent_message", {"output": normalized.get("output"), "input": normalized.get("input")}
    return normalized.get("tool_name") or step_type or "agent_message", normalized.get("tool_args") or {}


def evaluate_protocol_policy(action: str, params: Any):
    text = params
    if isinstance(params, (dict, list)):
        import json
        text = json.dumps(params, ensure_ascii=False, default=str)
    return get_policy_engine().evaluate(action or "agent_message", str(text or ""))


def _touch_session(
    agent_id: str,
    agent_name: str,
    session_id: str,
    chain_id: str,
    source_ip: str = None,
    last_step_type: str = None,
    last_decision: str = None,
    event_id: int = None,
    tool_name: str = None,
    risk_score: int = None,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    key = session_id or chain_id or agent_id
    with _SESSION_LOCK:
        item = _SESSIONS.setdefault(key, {
            "agent_id": agent_id,
            "agent_name": agent_name or agent_id,
            "session_id": session_id,
            "chain_id": chain_id,
            "source_ip": source_ip,
            "created_at": now,
            "event_count": 0,
            "risk_score": 0,
        })
        item.update({
            "agent_id": agent_id or item.get("agent_id"),
            "agent_name": agent_name or item.get("agent_name") or agent_id,
            "session_id": session_id or item.get("session_id"),
            "chain_id": chain_id or item.get("chain_id"),
            "source_ip": source_ip or item.get("source_ip"),
            "last_seen": now,
            "last_step_type": last_step_type or item.get("last_step_type"),
            "last_decision": last_decision or item.get("last_decision"),
            "last_event_id": event_id or item.get("last_event_id"),
            "last_tool": tool_name or item.get("last_tool"),
            "risk_score": max(int(item.get("risk_score") or 0), int(risk_score or 0)),
        })
        item["event_count"] = int(item.get("event_count") or 0) + 1
        return dict(item)


def _protocol_detail(normalized: Dict[str, Any], action: str, params: Any) -> str:
    target = _target_from_params(params)
    return (
        f"Agent={normalized.get('agent_id')}, "
        f"会话={normalized.get('session_id')}, "
        f"步骤={normalized.get('step_type')}, "
        f"动作={action or '-'}, "
        f"目标={target or '-'}"
    )


def _target_from_params(params: Any) -> str:
    if isinstance(params, dict):
        for key in ("path", "file", "filename", "url", "endpoint", "to", "target", "query"):
            if params.get(key):
                return str(params.get(key))[:160]
    return str(params or "")[:160]


def _rule_from_steps(steps: List[Dict[str, Any]]) -> str:
    for step in steps:
        if step.get("rule_id"):
            return step.get("rule_id")
        evidence = step.get("evidence") or {}
        matched = evidence.get("matched_rules") or []
        if matched:
            return matched[0].get("id") or matched[0].get("rule_id")
    return None


def _event_brief(event: Dict[str, Any]) -> Dict[str, Any]:
    meta = event.get("metadata") or {}
    return {
        "id": event.get("id"),
        "time": event.get("time"),
        "agent_id": meta.get("agent_id"),
        "agent_name": meta.get("agent_name"),
        "session_id": meta.get("session_id"),
        "step_type": meta.get("step_type"),
        "decision": meta.get("decision") or event.get("status_code"),
        "tool_name": event.get("tool_name") or event.get("action"),
        "rule_id": event.get("rule_id"),
        "chain_id": event.get("chain_id"),
        "detail": event.get("detail"),
        "risk_score": event.get("confidence") or 0,
    }


def _normalize_decision(value: Any) -> str:
    text = str(value or "").lower()
    if text in {"block", "blocked", "deny"}:
        return "blocked"
    if text in {"confirm", "ask", "pending", "review"}:
        return "confirm"
    if text in {"timeout", "error"}:
        return "error"
    return "allowed"


def _status_from_decision(decision: str, ingest: bool = False) -> str:
    if decision == Action.BLOCK.value or decision == "block":
        return "已阻断"
    if decision == Action.CONFIRM.value or decision == "confirm":
        return "需确认"
    return "已记录" if ingest else "已放行"


def _threat_from_decision(decision: str, severity: int) -> str:
    if decision in {"block", "blocked"} or severity >= 80:
        return "high"
    if decision == "confirm" or severity >= 45:
        return "medium"
    return "low"


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _clamp_int(value: Any, default: int, lower: int, upper: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(lower, min(number, upper))
