"""多轮对话与上下文污染防护服务"""
from typing import Dict, List, Any
import uuid

from services.detection import hybrid_detect
from services.output_guard import scan_output

MAX_TURNS = 20
_ALLOWED_ROLES = {"system", "user", "assistant", "tool", "memory"}


def create_session(seed_turns: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    turns = []
    if seed_turns:
        for turn in seed_turns[:MAX_TURNS]:
            turns.append(_normalize_turn(turn, len(turns)))
    session_id = f"conv-{uuid.uuid4().hex[:10]}"
    return {
        "session_id": session_id,
        "turns": turns,
        "summary": summarize_session(turns),
    }


def append_turns(existing_turns: List[Dict[str, Any]], new_turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    turns = [dict(t) for t in (existing_turns or [])][:MAX_TURNS]
    for turn in (new_turns or []):
        if len(turns) >= MAX_TURNS:
            break
        turns.append(_normalize_turn(turn, len(turns)))
    return {
        "turns": turns,
        "summary": summarize_session(turns),
    }


def evaluate_session(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    normalized_turns = [_normalize_turn(turn, idx) for idx, turn in enumerate((turns or [])[:MAX_TURNS])]
    cumulative_score = 0
    alerts = []
    timeline = []
    polluted_sources = []
    last_reason = "未发现明显风险"

    for idx, turn in enumerate(normalized_turns):
        context = _compose_context(normalized_turns[: idx + 1])
        current_text = turn.get("content", "")
        current_malicious, current_reason, current_conf = hybrid_detect(current_text or context)
        context_malicious, context_reason, context_conf = hybrid_detect(context)

        current_score = _score_from_confidence(current_conf)
        context_score = _score_from_confidence(context_conf)
        turn_score = max(current_score, context_score)
        cumulative_score += turn_score

        if current_malicious or context_malicious:
            reason = current_reason if current_malicious else context_reason
            last_reason = reason
            alert_type = _infer_alert_type(turn)
            alert = {
                "turn_index": idx,
                "role": turn.get("role"),
                "reason": reason,
                "risk_score": turn_score,
                "threat_level": (current_conf if current_malicious else context_conf).get("threat_level", "medium"),
                "alert_type": alert_type,
            }
            alerts.append(alert)
            polluted_sources.append({
                "turn_index": idx,
                "role": turn.get("role"),
                "content_preview": current_text[:80],
                "alert_type": alert_type,
            })

        timeline.append({
            "turn_index": idx,
            "role": turn.get("role"),
            "content": current_text,
            "risk_score": turn_score,
            "cumulative_risk": cumulative_score,
            "context_threat_level": context_conf.get("threat_level", "none"),
            "flags": _turn_flags(turn, current_text),
            "reason": current_reason if current_malicious else (context_reason if context_malicious else "未触发告警"),
        })

    status = "malicious" if alerts else "safe"
    escalation = _escalation_path(timeline)
    return {
        "status": status,
        "alerts": alerts,
        "timeline": timeline,
        "turn_count": len(normalized_turns),
        "cumulative_risk": cumulative_score,
        "risk_level": _risk_level_from_score(cumulative_score),
        "polluted_sources": polluted_sources,
        "escalation_path": escalation,
        "summary": summarize_session(normalized_turns),
        "reason": last_reason,
        # ── 输出内容安全扫描（第10条"化解应用衍生风险"）───────────────
        "output_guard": _scan_conversation_outputs(normalized_turns),
    }


def _scan_conversation_outputs(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """扫描对话中 assistant/tool 角色的输出是否泄露敏感信息"""
    output_findings = []
    total_outputs = 0
    for turn in turns:
        role = turn.get("role", "")
        content = turn.get("content", "")
        if role in ("assistant", "tool") and content:
            total_outputs += 1
            has_leak, findings = scan_output(content)
            if has_leak:
                output_findings.append({
                    "turn_index": turn.get("turn_index"),
                    "role": role,
                    "preview": content[:80],
                    "findings": findings,
                })
    return {
        "total_outputs": total_outputs,
        "leaked_outputs": len(output_findings),
        "leak_detected": len(output_findings) > 0,
        "details": output_findings,
    }


def summarize_session(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    normalized_turns = turns or []
    by_role: Dict[str, int] = {}
    for turn in normalized_turns:
        role = turn.get("role", "user")
        by_role[role] = by_role.get(role, 0) + 1
    return {
        "turn_count": len(normalized_turns),
        "roles": by_role,
        "has_memory_turn": by_role.get("memory", 0) > 0,
        "has_tool_turn": by_role.get("tool", 0) > 0,
    }


def _normalize_turn(turn: Dict[str, Any], idx: int) -> Dict[str, Any]:
    raw_role = str((turn or {}).get("role", "user")).strip().lower() or "user"
    role = raw_role if raw_role in _ALLOWED_ROLES else "user"
    content = str((turn or {}).get("content", "")).strip()
    return {
        "turn_index": idx,
        "role": role,
        "content": content,
        "label": (turn or {}).get("label") or f"{role}-{idx + 1}",
    }


def _compose_context(turns: List[Dict[str, Any]]) -> str:
    return "\n".join([f"[{turn.get('role', 'user')}] {turn.get('content', '')}" for turn in turns])


def _score_from_confidence(conf: Dict[str, Any]) -> int:
    if not isinstance(conf, dict):
        return 0
    return int(conf.get("combined", 0) or 0)


def _risk_level_from_score(score: int) -> str:
    if score >= 180:
        return "critical"
    if score >= 120:
        return "high"
    if score >= 60:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _infer_alert_type(turn: Dict[str, Any]) -> str:
    role = turn.get("role")
    if role == "memory":
        return "memory_poisoning"
    if role == "tool":
        return "tool_hijack"
    return "prompt_injection"


def _turn_flags(turn: Dict[str, Any], text: str) -> List[str]:
    flags = []
    lower = (text or "").lower()
    if turn.get("role") == "memory":
        flags.append("memory_context")
    if turn.get("role") == "tool":
        flags.append("tool_context")
    if any(keyword in lower for keyword in ["ignore", "忽略", "override", "system", "提示词"]):
        flags.append("instruction_override")
    if any(keyword in lower for keyword in ["password", "secret", "token", "api key", "系统提示词"]):
        flags.append("sensitive_target")
    return flags


def _escalation_path(timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    path = []
    previous = 0
    for item in timeline:
        score = int(item.get("cumulative_risk", 0) or 0)
        if score > previous:
            path.append({
                "turn_index": item.get("turn_index"),
                "role": item.get("role"),
                "risk": score,
                "reason": item.get("reason"),
            })
        previous = score
    return path
