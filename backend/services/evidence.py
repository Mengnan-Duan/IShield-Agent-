"""v4.8 evidence normalization for runtime audit chains.

This module is deliberately independent from storage/routes so the UI can rely
on one stable evidence contract no matter whether an event came from detection,
policy evaluation, sandbox execution, or Agent cluster audit.
"""
from typing import Any, Dict, List, Optional


STATUS_LABELS = {
    "blocked": "已阻断",
    "confirm": "需确认",
    "allowed": "已放行",
    "passed": "已通过",
    "running": "处理中",
    "review": "待复核",
    "error": "异常",
    "skipped": "未执行",
    "pending": "待处理",
    "unknown": "已记录",
}

STAGE_LABELS = {
    "request": "请求接入",
    "request_received": "请求接入",
    "input": "输入检测",
    "detect": "输入检测",
    "detection": "输入检测",
    "input_detection": "输入检测",
    "policy": "策略裁决",
    "policy_evaluated": "策略裁决",
    "policy_blocked": "策略阻断",
    "policy_confirm": "人工确认",
    "tool": "工具执行",
    "tool_finished": "工具执行",
    "sandbox": "沙箱执行",
    "audit": "审计落库",
    "output": "输出检测",
    "runtime": "运行时结论",
    "runtime_conclusion": "运行时结论",
    "conclusion": "最终结论",
    "none": "全链路通过",
    "unknown": "未标注阶段",
}

RISK_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "none": "无风险",
    "unknown": "待评估",
}


def build_evidence_packet(events: List[Dict[str, Any]], chain_id: str = None,
                          focus_event: Dict[str, Any] = None) -> Dict[str, Any]:
    ordered = sorted(events or [], key=lambda item: item.get("id") or 0)
    latest = focus_event or (ordered[-1] if ordered else {})
    conclusion = _latest_runtime_conclusion(ordered)
    meta = _metadata(conclusion)
    steps = meta.get("steps") if isinstance(meta.get("steps"), list) else []
    tool_evidence = meta.get("tool_evidence") if isinstance(meta.get("tool_evidence"), dict) else None
    policy_trace = _first_dict(meta.get("policy_trace"), _find_metadata_value(ordered, "policy_trace"))
    risk_assessment = _first_dict(meta.get("risk_assessment"), _find_metadata_value(ordered, "risk_assessment"))

    decision = _status_code(
        meta.get("decision")
        or meta.get("runtime_status")
        or (tool_evidence or {}).get("decision")
        or (conclusion or {}).get("status_code")
        or _chain_status(ordered)
    )
    blocked_at = (
        meta.get("blocked_at")
        or (tool_evidence or {}).get("blocked_at")
        or _blocked_at_from_steps(steps)
        or ("none" if decision in {"allowed", "passed"} else "unknown")
    )
    risk_score = _max_risk(ordered, conclusion, risk_assessment)
    risk_level = _risk_level(risk_score, latest, conclusion, risk_assessment)
    source_ip = (latest or {}).get("source_ip") or _first_value(ordered, "source_ip")
    tool = (tool_evidence or {}).get("tool") or (latest or {}).get("tool_name") or (latest or {}).get("action") or _first_value(ordered, "tool_name")
    target = (tool_evidence or {}).get("target") or (latest or {}).get("target") or _first_value(ordered, "target")
    rule_id = (latest or {}).get("rule_id") or _first_value(reversed(ordered), "rule_id") or (policy_trace or {}).get("triggered_rule")

    title = _verdict_title(decision, blocked_at)
    summary = _summary(decision, blocked_at, tool, target, conclusion, tool_evidence)
    recommendation = _recommendation(decision, blocked_at, tool, policy_trace, tool_evidence, risk_assessment)
    evidence_items = _evidence_items(ordered, latest, tool_evidence, policy_trace, risk_assessment, source_ip, tool, target, rule_id)
    timeline = _timeline(ordered, steps, decision, blocked_at)

    packet = {
        "version": "v4.8",
        "chain_id": chain_id or (latest or {}).get("chain_id") or _first_value(ordered, "chain_id"),
        "event_id": (latest or {}).get("id"),
        "verdict": {
            "status_code": decision,
            "status_label": STATUS_LABELS.get(decision, STATUS_LABELS["unknown"]),
            "title": title,
            "summary": summary,
            "conclusion": summary,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_label": RISK_LABELS.get(risk_level, risk_level),
            "blocked_at": blocked_at,
            "blocked_at_label": stage_label(blocked_at),
            "recommendation": recommendation,
        },
        "actors": {
            "source_ip": source_ip,
            "agent_id": (latest or {}).get("agent_id") or _metadata(latest).get("agent_id"),
            "tool": tool,
            "target": target,
            "rule_id": rule_id,
        },
        "timeline": timeline,
        "evidence_items": evidence_items,
        "tool_evidence": tool_evidence,
        "policy_evidence": _policy_evidence(policy_trace, rule_id),
        "risk_assessment": risk_assessment,
        "risk_factors": _risk_factors(risk_assessment),
        "stats": {
            "event_count": len(ordered),
            "evidence_count": len(evidence_items),
            "stage_count": len({item.get("stage") for item in timeline if item.get("stage")}),
        },
    }
    try:
        from services.remediation import build_remediation_plan, list_remediation_actions
        action_records = list_remediation_actions(chain_id=packet.get("chain_id"), limit=100) if packet.get("chain_id") else []
        packet["remediation"] = build_remediation_plan(packet, action_records=action_records)
    except Exception:
        packet["remediation"] = None
    return packet


def event_evidence_brief(event: Dict[str, Any]) -> Dict[str, Any]:
    packet = build_evidence_packet([event], event.get("chain_id"), event)
    verdict = packet["verdict"]
    return {
        "title": verdict["title"],
        "summary": verdict["summary"],
        "status_code": verdict["status_code"],
        "status_label": verdict["status_label"],
        "risk_score": verdict["risk_score"],
        "blocked_at": verdict["blocked_at"],
        "blocked_at_label": verdict["blocked_at_label"],
        "recommendation": verdict["recommendation"],
    }


def status_label(code: str) -> str:
    return STATUS_LABELS.get(_status_code(code), STATUS_LABELS["unknown"])


def stage_label(stage: str) -> str:
    if not stage:
        return STAGE_LABELS["unknown"]
    key = str(stage).lower()
    if key in STAGE_LABELS:
        return STAGE_LABELS[key]
    if "detect" in key:
        return STAGE_LABELS["detection"]
    if "policy" in key:
        return STAGE_LABELS["policy"]
    if "tool" in key or "sandbox" in key:
        return STAGE_LABELS["tool"]
    if "runtime" in key or "conclusion" in key:
        return STAGE_LABELS["runtime_conclusion"]
    return str(stage)


def _metadata(event: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    meta = (event or {}).get("metadata")
    return meta if isinstance(meta, dict) else {}


def _status_code(value: Any) -> str:
    raw = str(value or "").lower()
    if raw in STATUS_LABELS:
        return raw
    if raw == "deny":
        return "blocked"
    if raw == "allow":
        return "allowed"
    if raw == "ask":
        return "confirm"
    if any(token in raw for token in ("block", "deny", "reject", "阻断", "拦截", "拒绝", "高危")):
        return "blocked"
    if any(token in raw for token in ("confirm", "review", "pending", "ask", "确认", "复核", "待")):
        return "confirm"
    if any(token in raw for token in ("error", "timeout", "fail", "异常", "失败", "超时")):
        return "error"
    if any(token in raw for token in ("allow", "pass", "executed", "mock", "通过", "放行", "完成", "成功")):
        return "allowed"
    if any(token in raw for token in ("running", "started", "处理中", "执行中")):
        return "running"
    return "unknown"


def _chain_status(events: List[Dict[str, Any]]) -> str:
    codes = {_status_code(event.get("status_code") or event.get("status") or event.get("stage")) for event in events or []}
    for code in ("blocked", "confirm", "error", "running", "allowed"):
        if code in codes:
            return code
    return "unknown"


def _latest_runtime_conclusion(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for event in sorted(events or [], key=lambda item: item.get("id") or 0, reverse=True):
        meta = _metadata(event)
        if event.get("stage") == "runtime_conclusion" or event.get("category") == "runtime_conclusion" or isinstance(meta.get("steps"), list):
            return event
    return None


def _blocked_at_from_steps(steps: List[Dict[str, Any]]) -> str:
    for step in steps or []:
        if _status_code(step.get("status")) in {"blocked", "confirm", "error"}:
            stage = str(step.get("stage") or "").lower()
            if "detect" in stage:
                return "detection"
            if "policy" in stage:
                return "policy"
            if "tool" in stage or "sandbox" in stage:
                return "tool"
            return step.get("stage") or "unknown"
    return "none"


def _max_risk(events: List[Dict[str, Any]], conclusion: Dict[str, Any], risk_assessment: Dict[str, Any]) -> int:
    scores = []
    for event in events or []:
        try:
            scores.append(int(event.get("confidence") or event.get("risk_score") or 0))
        except (TypeError, ValueError):
            pass
    for source in (conclusion, risk_assessment):
        if isinstance(source, dict):
            try:
                scores.append(int(source.get("confidence") or source.get("risk_score") or 0))
            except (TypeError, ValueError):
                pass
    return max(scores or [0])


def _risk_level(score: int, latest: Dict[str, Any], conclusion: Dict[str, Any], assessment: Dict[str, Any]) -> str:
    explicit = None
    for source in (assessment, conclusion, latest):
        if isinstance(source, dict):
            explicit = source.get("risk_level") or source.get("threat_level")
            if explicit:
                break
    if explicit:
        return str(explicit).lower()
    if score >= 80:
        return "high"
    if score >= 45:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _verdict_title(decision: str, blocked_at: str) -> str:
    if decision == "blocked":
        return f"已在{stage_label(blocked_at)}阶段阻断"
    if decision == "confirm":
        return f"已在{stage_label(blocked_at)}阶段进入确认队列"
    if decision == "allowed":
        return "已放行并完成审计"
    if decision == "error":
        return "链路异常，已保留审计证据"
    return "链路已记录，等待进一步分析"


def _summary(decision: str, blocked_at: str, tool: str, target: str,
             conclusion: Dict[str, Any], tool_evidence: Dict[str, Any]) -> str:
    existing = (tool_evidence or {}).get("summary") or (conclusion or {}).get("detail")
    if existing and not _looks_mojibake(existing):
        return existing
    subject = tool or "工具调用"
    target_part = f"，目标为 {target}" if target else ""
    if decision == "blocked":
        return f"{subject}{target_part} 被安全网关拦截，阻断点位于{stage_label(blocked_at)}。"
    if decision == "confirm":
        return f"{subject}{target_part} 命中中风险策略，已进入人工确认队列。"
    if decision == "allowed":
        return f"{subject}{target_part} 通过检测、策略和沙箱审计，已写入证据链。"
    if decision == "error":
        return f"{subject}{target_part} 执行异常，系统已记录上下文和失败证据。"
    return f"{subject}{target_part} 已进入审计链路。"


def _recommendation(decision: str, blocked_at: str, tool: str, policy_trace: Dict[str, Any],
                    tool_evidence: Dict[str, Any], risk_assessment: Dict[str, Any]) -> str:
    for source in (tool_evidence, policy_trace, risk_assessment):
        if isinstance(source, dict):
            value = source.get("recommendation")
            if value and not _looks_mojibake(value):
                return value
    if decision == "blocked":
        return f"保持{stage_label(blocked_at)}阻断策略，将该样本加入回归集，并复核同源 Agent、Token 和 IP 的后续行为。"
    if decision == "confirm":
        return "保留人工确认策略，要求操作者补充业务目的、审批记录和执行后审计。"
    if decision == "allowed":
        return "保留全链路审计记录，持续观察相同来源的工具调用频率和目标变化。"
    if decision == "error":
        return "排查异常阶段日志，必要时临时收紧工具权限并重放该链路。"
    return "继续聚合链路证据，等待更多运行时事件形成稳定结论。"


def _timeline(events: List[Dict[str, Any]], steps: List[Dict[str, Any]], decision: str, blocked_at: str) -> List[Dict[str, Any]]:
    if steps:
        return [
            {
                "index": idx + 1,
                "stage": step.get("stage") or "runtime",
                "stage_label": stage_label(step.get("stage")),
                "title": step.get("title") or stage_label(step.get("stage")),
                "status_code": _status_code(step.get("status")),
                "status_label": STATUS_LABELS.get(_status_code(step.get("status")), step.get("status") or "已记录"),
                "detail": step.get("detail") or "该阶段已完成审计。",
                "risk_score": int(step.get("risk_score") or 0),
                "rule_id": step.get("rule_id"),
                "evidence": step.get("evidence") or {},
            }
            for idx, step in enumerate(steps)
        ]

    timeline = []
    for idx, event in enumerate(events or []):
        status_code = _status_code(event.get("status_code") or event.get("status"))
        timeline.append({
            "index": idx + 1,
            "event_id": event.get("id"),
            "time": event.get("time"),
            "stage": event.get("stage") or event.get("category") or "audit",
            "stage_label": stage_label(event.get("stage") or event.get("category")),
            "title": event.get("type") or event.get("action") or "审计事件",
            "status_code": status_code,
            "status_label": STATUS_LABELS.get(status_code, event.get("status") or "已记录"),
            "detail": event.get("detail") or "该事件已写入审计链路。",
            "risk_score": int(event.get("confidence") or 0),
            "rule_id": event.get("rule_id"),
        })

    if not timeline:
        timeline.append({
            "index": 1,
            "stage": blocked_at or "runtime",
            "stage_label": stage_label(blocked_at),
            "title": "运行时结论",
            "status_code": decision,
            "status_label": STATUS_LABELS.get(decision, "已记录"),
            "detail": _summary(decision, blocked_at, "", "", None, None),
            "risk_score": 0,
        })
    return timeline


def _evidence_items(events: List[Dict[str, Any]], latest: Dict[str, Any], tool_evidence: Dict[str, Any],
                    policy_trace: Dict[str, Any], risk_assessment: Dict[str, Any],
                    source_ip: str, tool: str, target: str, rule_id: str) -> List[Dict[str, Any]]:
    items = []
    if source_ip:
        items.append({"type": "actor", "label": "来源 IP", "value": source_ip, "severity": "info"})
    if tool:
        items.append({"type": "tool", "label": "工具", "value": tool, "severity": "info"})
    if target:
        items.append({"type": "target", "label": "目标", "value": target, "severity": "warning"})
    if rule_id:
        items.append({"type": "policy", "label": "命中规则", "value": rule_id, "severity": "danger"})

    for idx, value in enumerate((tool_evidence or {}).get("evidence") or []):
        items.append({"type": "tool_evidence", "label": f"工具证据 {idx + 1}", "value": value, "severity": "warning"})

    keywords = (policy_trace or {}).get("matched_keywords") or []
    if keywords:
        items.append({"type": "policy", "label": "命中关键词", "value": "、".join(map(str, keywords[:6])), "severity": "danger"})

    for factor in _risk_factors(risk_assessment)[:4]:
        items.append({
            "type": "risk_factor",
            "label": factor.get("factor_label") or "风险因子",
            "value": factor.get("reason") or factor.get("factor") or "-",
            "severity": "warning",
        })

    if latest and latest.get("detail"):
        items.append({"type": "event_detail", "label": "事件摘要", "value": latest.get("detail"), "severity": "info"})
    return items[:12]


def _policy_evidence(policy_trace: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
    policy_trace = policy_trace or {}
    return {
        "rule_id": rule_id or policy_trace.get("triggered_rule"),
        "action": policy_trace.get("action"),
        "severity": policy_trace.get("severity"),
        "matched_keywords": policy_trace.get("matched_keywords") or [],
        "matched_rules": policy_trace.get("matched_rules") or [],
        "recommendation": policy_trace.get("recommendation"),
    }


def _risk_factors(assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(assessment, dict):
        return []
    factors = assessment.get("risk_factors") or assessment.get("top_risk_factors") or []
    return factors if isinstance(factors, list) else []


def _find_metadata_value(events: List[Dict[str, Any]], key: str):
    for event in reversed(list(events or [])):
        meta = _metadata(event)
        if key in meta:
            return meta.get(key)
    return None


def _first_dict(*values):
    for value in values:
        if isinstance(value, dict):
            return value
    return None


def _first_value(events, key: str):
    for event in events or []:
        if isinstance(event, dict) and event.get(key):
            return event.get(key)
    return None


def _looks_mojibake(value: str) -> bool:
    text = str(value or "")
    return any(token in text for token in ("鈥", "宸", "鏃", "绛", "娌", "閾", "璇", "濞"))
