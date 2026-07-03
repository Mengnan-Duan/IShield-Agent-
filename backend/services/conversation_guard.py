"""多轮对话与上下文污染防护服务"""
from typing import Dict, List, Any
import uuid
import re
import time

from services.detection import hybrid_detect
from services.output_guard import scan_output

MAX_TURNS = 20
_ALLOWED_ROLES = {"system", "user", "assistant", "tool", "memory"}

_FAST_PATTERNS = [
    ("memory_poisoning", 46, "记忆中毒", ["记住", "长期记忆", "memory", "以后都", "安全告警均为误报", "告警均为误报", "自动允许", "不要再提醒"]),
    ("tool_hijack", 42, "工具劫持", ["send_email", "read_file", "write_file", "call_api", "query_db", "run_code", "调用工具", "外部邮件", "发送给"]),
    ("rag_poisoning", 38, "RAG 污染", ["知识库", "文档说", "检索结果", "rag", "来源可信", "系统规则已更新", "忽略安全策略"]),
    ("prompt_injection", 44, "提示注入", ["忽略之前", "ignore previous", "ignore all", "override", "绕过", "无视规则", "不要遵守", "系统提示词", "开发者消息"]),
    ("data_leak", 40, "敏感信息泄露", ["api_key", "secret", "token", "password", "管理员口令", "密钥", ".env", "凭证", "cookie"]),
]


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


def evaluate_session(turns: List[Dict[str, Any]], fast: bool = True) -> Dict[str, Any]:
    if fast:
        return evaluate_session_fast(turns)
    return evaluate_session_precise(turns)


def evaluate_session_fast(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    start = time.time()
    normalized_turns = [_normalize_turn(turn, idx) for idx, turn in enumerate((turns or [])[:MAX_TURNS])]
    cumulative_score = 0
    alerts = []
    timeline = []
    polluted_sources = []
    inherited_risk = 0
    last_reason = "未发现明确风险"

    for idx, turn in enumerate(normalized_turns):
        current_text = turn.get("content", "")
        scan = _fast_turn_scan(turn, current_text, inherited_risk)
        turn_score = scan["risk_score"]
        cumulative_score += turn_score
        inherited_risk = max(0, min(30, inherited_risk + (12 if turn_score >= 35 else -4)))

        if turn_score > 0:
            last_reason = scan["reason"]
        if scan["alert"]:
            alert = {
                "turn_index": idx,
                "role": turn.get("role"),
                "reason": scan["reason"],
                "risk_score": turn_score,
                "threat_level": scan["threat_level"],
                "alert_type": scan["alert_type"],
            }
            alerts.append(alert)
            polluted_sources.append({
                "turn_index": idx,
                "role": turn.get("role"),
                "content_preview": current_text[:80],
                "alert_type": scan["alert_type"],
            })

        timeline.append({
            "turn_index": idx,
            "role": turn.get("role"),
            "content": current_text,
            "risk_score": turn_score,
            "cumulative_risk": cumulative_score,
            "context_threat_level": scan["threat_level"],
            "flags": scan["flags"],
            "reason": scan["reason"] if scan["alert"] else "未触发告警",
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
        "output_guard": _scan_conversation_outputs(normalized_turns),
        "engine": "conversation_fast",
        "elapsed_ms": round((time.time() - start) * 1000, 1),
    }


def evaluate_session_precise(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    start = time.time()
    normalized_turns = [_normalize_turn(turn, idx) for idx, turn in enumerate((turns or [])[:MAX_TURNS])]
    baseline = evaluate_session_fast(normalized_turns)
    context = _compose_context(normalized_turns)

    precise_malicious = False
    precise_reason = "精确复核未发现额外风险"
    precise_conf: Dict[str, Any] = {}
    try:
        precise_malicious, precise_reason, precise_conf = hybrid_detect(context)
    except Exception as exc:
        precise_reason = f"精确复核降级：{exc}"
        precise_conf = {"combined": 0, "threat_level": "none", "api_fallback": True}

    precise_score = _score_from_confidence(precise_conf)
    alerts = list(baseline.get("alerts", []))
    polluted_sources = list(baseline.get("polluted_sources", []))
    timeline = [dict(item) for item in baseline.get("timeline", [])]
    target_turn = _review_target_turn(timeline, normalized_turns)

    if precise_malicious and not _has_precise_alert(alerts):
        alerts.append({
            "turn_index": target_turn.get("turn_index", 0),
            "role": target_turn.get("role", "user"),
            "reason": "精确复核：" + precise_reason,
            "risk_score": max(precise_score, target_turn.get("risk_score", 0) or 0),
            "threat_level": precise_conf.get("threat_level", "medium"),
            "alert_type": _infer_alert_type(target_turn),
            "review_engine": "hybrid_precise",
        })
        polluted_sources.append({
            "turn_index": target_turn.get("turn_index", 0),
            "role": target_turn.get("role", "user"),
            "content_preview": target_turn.get("content", "")[:80],
            "alert_type": _infer_alert_type(target_turn),
        })

    if timeline:
        idx = int(target_turn.get("turn_index", len(timeline) - 1) or 0)
        idx = max(0, min(idx, len(timeline) - 1))
        timeline[idx]["precise_review"] = {
            "malicious": precise_malicious,
            "reason": precise_reason,
            "score": precise_score,
            "threat_level": precise_conf.get("threat_level", "none"),
        }
        if precise_malicious:
            timeline[idx]["risk_score"] = max(timeline[idx].get("risk_score", 0) or 0, precise_score)
            timeline[idx]["context_threat_level"] = precise_conf.get("threat_level", timeline[idx].get("context_threat_level", "medium"))
            timeline[idx]["reason"] = "精确复核：" + precise_reason

    cumulative_score = max(int(baseline.get("cumulative_risk", 0) or 0), precise_score)
    status = "malicious" if alerts or precise_malicious else "safe"
    return {
        "status": status,
        "alerts": alerts,
        "timeline": timeline,
        "turn_count": len(normalized_turns),
        "cumulative_risk": cumulative_score,
        "risk_level": _risk_level_from_score(cumulative_score),
        "polluted_sources": polluted_sources,
        "escalation_path": _escalation_path(timeline),
        "summary": summarize_session(normalized_turns),
        "reason": precise_reason if precise_malicious else baseline.get("reason", precise_reason),
        "output_guard": baseline.get("output_guard", _scan_conversation_outputs(normalized_turns)),
        "engine": "hybrid_precise",
        "review_mode": "bounded_context",
        "review_checks": 1,
        "precise_review": {
            "malicious": precise_malicious,
            "reason": precise_reason,
            "score": precise_score,
            "threat_level": precise_conf.get("threat_level", "none"),
            "api_fallback": precise_conf.get("api_fallback", False),
            "detection_time_ms": precise_conf.get("detection_time_ms"),
        },
        "elapsed_ms": round((time.time() - start) * 1000, 1),
    }


def _fast_turn_scan(turn: Dict[str, Any], text: str, inherited_risk: int = 0) -> Dict[str, Any]:
    lower = (text or "").lower()
    role = turn.get("role", "user")
    matched = []
    score = inherited_risk
    alert_type = _infer_alert_type(turn)

    for pattern_type, weight, label, keywords in _FAST_PATTERNS:
        hits = [kw for kw in keywords if kw.lower() in lower]
        if hits:
            matched.append({"type": pattern_type, "label": label, "hits": hits[:3], "weight": weight})
            score += weight + min(18, (len(hits) - 1) * 6)
            if pattern_type in ("memory_poisoning", "tool_hijack", "rag_poisoning"):
                alert_type = pattern_type

    if role == "memory":
        score += 22
        if not any(item["type"] == "memory_poisoning" for item in matched):
            matched.append({"type": "memory_poisoning", "label": "记忆上下文", "hits": ["memory"], "weight": 22})
            alert_type = "memory_poisoning"
    elif role == "tool":
        score += 18
        if not any(item["type"] == "tool_hijack" for item in matched):
            matched.append({"type": "tool_hijack", "label": "工具上下文", "hits": ["tool"], "weight": 18})
            alert_type = "tool_hijack"
    elif role == "system" and any(kw in lower for kw in ["更新规则", "忽略", "override"]):
        score += 18

    if re.search(r"(http://|https://|169\.254\.169\.254|localhost|127\.0\.0\.1)", lower):
        score += 16
        matched.append({"type": "external_egress", "label": "外联目标", "hits": ["url"], "weight": 16})

    score = max(0, min(100, score))
    alert = score >= 35 or bool(matched)
    if score >= 75:
        threat = "critical"
    elif score >= 55:
        threat = "high"
    elif score >= 35:
        threat = "medium"
    elif score > 0:
        threat = "low"
    else:
        threat = "none"
    labels = [item["label"] for item in matched]
    reason = "、".join(labels[:4]) if labels else "未发现明确污染信号"
    flags = _turn_flags(turn, text)
    flags.extend([item["type"] for item in matched if item["type"] not in flags])
    return {
        "alert": alert,
        "risk_score": score,
        "threat_level": threat,
        "alert_type": alert_type,
        "reason": reason,
        "flags": flags,
    }


def _review_target_turn(timeline: List[Dict[str, Any]], turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    if timeline:
        risky = max(timeline, key=lambda item: int(item.get("risk_score", 0) or 0))
        if int(risky.get("risk_score", 0) or 0) > 0:
            return risky
    if turns:
        return turns[-1]
    return {"turn_index": 0, "role": "user", "content": ""}


def _has_precise_alert(alerts: List[Dict[str, Any]]) -> bool:
    return any(item.get("review_engine") == "hybrid_precise" for item in alerts or [])


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
