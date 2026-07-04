"""IShield v6.0 operational dashboard aggregation service."""
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.analytics import get_analytics
from services.events import get_chain_summary, get_events_from_db, get_rule_hit_summary, get_stats
from services.playbook_engine import regression_overview
from services.policy import get_policy_engine
from services.runtime_diagnostics import latest_diagnostic
from services.runtime_protocol import list_sessions


def build_dashboard_overview(limit: int = 12) -> Dict[str, Any]:
    """Aggregate the main product workflow into one dashboard payload."""
    limit = _limit(limit, default=12, lower=5, upper=50)
    stats = get_stats()
    analytics = get_analytics(days=7)
    events = get_events_from_db(limit=80)
    chains = get_chain_summary(limit=limit)
    rule_hits = get_rule_hit_summary(limit=3000, per_rule_limit=3)
    policy_summary = get_policy_engine().summary()
    runtime_sessions = list_sessions(limit=20)
    runtime_diagnostic = latest_diagnostic()
    diagnostic_summary = runtime_diagnostic.get("summary") or runtime_diagnostic
    playbook_regression = regression_overview()
    playbook_summary = playbook_regression.get("summary") or {}

    open_chains = []
    closed_chains = []
    for chain in chains:
        remediation = chain.get("remediation") or {}
        state = remediation.get("state")
        if state == "closed":
            closed_chains.append(chain)
        elif chain.get("status_code") in {"blocked", "confirm", "error"}:
            open_chains.append(chain)

    active_rule_count = sum(1 for item in rule_hits if int(item.get("hit_count") or 0) > 0)
    rule_hit_count = sum(int(item.get("hit_count") or 0) for item in rule_hits)
    closure_sample = len(open_chains) + len(closed_chains)
    closure_rate = round((len(closed_chains) / closure_sample) * 100, 1) if closure_sample else 0.0
    risk_score = _risk_score(stats, chains, open_chains)

    return {
        "version": "v6.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mission": {
            "title": "Agent 安全监督作战驾驶舱",
            "summary": _mission_summary(stats, risk_score, len(open_chains), active_rule_count),
            "risk_score": risk_score,
            "risk_level": _risk_level(risk_score),
            "next_action": _next_action(open_chains, rule_hits, stats),
        },
        "kpis": {
            "total": stats.get("total", 0),
            "total_events": stats.get("total", 0),
            "today_total": stats.get("today_total", 0),
            "today_events": stats.get("today_total", 0),
            "blocked": stats.get("blocked", 0),
            "blocked_events": stats.get("blocked", 0),
            "passed": stats.get("passed", 0),
            "high_risk": stats.get("high_risk", 0),
            "threat_score": risk_score,
            "today_blocked": stats.get("today_blocked", 0),
            "block_rate": stats.get("block_rate", 0),
            "chain_total": stats.get("chain_total", 0),
            "open_chains": len(open_chains),
            "closed_chains": len(closed_chains),
            "closure_rate": closure_rate,
            "policy_rules": policy_summary.get("total", 0),
            "enabled_rules": policy_summary.get("enabled", 0),
            "active_rule_count": active_rule_count,
            "rule_hit_count": rule_hit_count,
            "external_agent_sessions": runtime_sessions.get("count", 0),
            "external_agent_blocked": runtime_sessions.get("blocked_sessions", 0),
            "runtime_diagnostic_coverage": diagnostic_summary.get("coverage", 0) if isinstance(diagnostic_summary, dict) else 0,
            "runtime_diagnostic_failed": diagnostic_summary.get("failed", 0) if isinstance(diagnostic_summary, dict) else 0,
            "playbook_regression_coverage": playbook_summary.get("coverage", 0) if isinstance(playbook_summary, dict) else 0,
            "playbook_regression_failed": playbook_summary.get("failed", 0) if isinstance(playbook_summary, dict) else 0,
        },
        "workflow": _workflow(chains, rule_hits, stats, closure_rate),
        "recent_events": [_event_brief(event) for event in events[:8]],
        "trend_7d": analytics.get("trend_7d", []),
        "trend_60m": analytics.get("trend_60m", []),
        "top_threats": analytics.get("top_threats", []),
        "top_tools": analytics.get("top_tools", []),
        "confidence_distribution": analytics.get("confidence_distribution", []),
        "severity_distribution": analytics.get("severity_distribution", []),
        "source_regions": analytics.get("source_regions", []),
        "recommendations": analytics.get("recommendations", []),
        "priority_chains": [_chain_brief(chain) for chain in (open_chains + chains)[:8]],
        "rule_hotspots": [_rule_brief(item) for item in rule_hits[:8]],
        "attack_surface": _attack_surface(rule_hits),
        "timeline": build_dashboard_timeline(events, chains),
        "system": {
            "policy_engine": "ready",
            "event_store": "ready",
            "runtime_protocol": "v6.0-ready",
            "runtime_diagnostics": "ready" if runtime_diagnostic.get("status") != "empty" else "waiting",
            "attack_playbooks": "ready" if playbook_regression.get("status") != "empty" else "waiting",
            "evidence_packet": "v6.0-ready",
            "remediation_loop": "ready",
        },
        "runtime_diagnostics": runtime_diagnostic,
        "playbook_regression": playbook_regression,
    }


def build_dashboard_timeline(events: List[Dict[str, Any]] = None, chains: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    events = events if events is not None else get_events_from_db(limit=80)
    chains = chains if chains is not None else get_chain_summary(limit=12)
    rows = []
    for event in events[:12]:
        rows.append({
            "type": "event",
            "time": event.get("time"),
            "title": event.get("type") or "审计事件",
            "detail": event.get("detail") or "--",
            "status_code": event.get("status_code"),
            "status_label": event.get("status_label"),
            "rule_id": event.get("rule_id"),
            "chain_id": event.get("chain_id"),
            "tool": event.get("tool_name") or event.get("action"),
            "risk_score": event.get("confidence") or 0,
        })
    for chain in chains[:6]:
        rows.append({
            "type": "chain",
            "time": chain.get("last_seen") or chain.get("ended_at") or chain.get("started_at"),
            "title": "攻击链 " + str(chain.get("status_label") or chain.get("status") or "已记录"),
            "detail": chain.get("runtime_conclusion") or chain.get("recommendation") or "--",
            "status_code": chain.get("status_code"),
            "status_label": chain.get("status_label"),
            "rule_id": ((chain.get("evidence_packet") or {}).get("policy_evidence") or {}).get("rule_id"),
            "chain_id": chain.get("chain_id"),
            "tool": chain.get("tool_name") or chain.get("action"),
            "risk_score": chain.get("max_confidence") or 0,
        })
    rows.sort(key=lambda item: str(item.get("time") or ""), reverse=True)
    return rows[:12]


def build_live_status() -> Dict[str, Any]:
    stats = get_stats()
    recent = get_events_from_db(limit=20)
    blocked_recent = sum(1 for item in recent if item.get("status_code") == "blocked")
    return {
        "version": "v6.0",
        "status": "ready",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events_seen": stats.get("total", 0),
        "recent_blocked": blocked_recent,
        "chain_total": stats.get("chain_total", 0),
        "message": "作战驾驶舱数据通道在线",
    }


def build_dashboard_live(limit: int = 25) -> Dict[str, Any]:
    limit = _limit(limit, default=25, lower=5, upper=100)
    events = get_events_from_db(limit=limit)
    return {
        "version": "v6.0",
        "count": len(events),
        "events": [_event_brief(event) for event in events],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _event_brief(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": event.get("id"),
        "time": event.get("time"),
        "type": event.get("type"),
        "detail": event.get("detail"),
        "status_code": event.get("status_code"),
        "status_label": event.get("status_label"),
        "threat_level": event.get("threat_level"),
        "confidence": event.get("confidence"),
        "rule_id": event.get("rule_id"),
        "chain_id": event.get("chain_id"),
        "tool": event.get("tool_name") or event.get("action"),
        "target": event.get("target"),
    }


def _chain_brief(chain: Dict[str, Any]) -> Dict[str, Any]:
    packet = chain.get("evidence_packet") or {}
    policy = packet.get("policy_evidence") or {}
    remediation = chain.get("remediation") or {}
    return {
        "chain_id": chain.get("chain_id"),
        "last_seen": chain.get("last_seen") or chain.get("ended_at"),
        "status_code": chain.get("status_code"),
        "status_label": chain.get("status_label"),
        "risk_score": chain.get("max_confidence"),
        "rule_id": policy.get("rule_id") or (packet.get("actors") or {}).get("rule_id"),
        "tool": chain.get("tool_name") or chain.get("action"),
        "target": chain.get("target"),
        "summary": chain.get("runtime_conclusion") or chain.get("recommendation"),
        "remediation": {
            "state": remediation.get("state"),
            "state_label": remediation.get("state_label"),
            "progress": remediation.get("progress"),
            "next_action": remediation.get("next_action"),
        },
    }


def _rule_brief(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": item.get("rule_id"),
        "hit_count": item.get("hit_count") or 0,
        "blocked_count": item.get("blocked_count") or 0,
        "confirm_count": item.get("confirm_count") or 0,
        "last_hit_at": item.get("last_hit_at"),
        "chain_ids": item.get("chain_ids") or [],
        "recent_events": item.get("recent_events") or [],
    }


def _workflow(chains: List[Dict[str, Any]], rule_hits: List[Dict[str, Any]], stats: Dict[str, Any], closure_rate: float) -> List[Dict[str, Any]]:
    blocked = int(stats.get("blocked") or 0)
    chain_total = int(stats.get("chain_total") or 0)
    active_rules = sum(1 for item in rule_hits if int(item.get("hit_count") or 0) > 0)
    return [
        {"key": "attack", "label": "攻击输入", "value": stats.get("total", 0), "state": "done" if stats.get("total") else "idle"},
        {"key": "decision", "label": "策略裁决", "value": blocked, "state": "blocked" if blocked else "idle"},
        {"key": "evidence", "label": "证据链", "value": chain_total, "state": "done" if chain_total else "idle"},
        {"key": "policy", "label": "规则命中", "value": active_rules, "state": "done" if active_rules else "idle"},
        {"key": "closure", "label": "处置闭环", "value": f"{closure_rate}%", "state": "done" if closure_rate >= 80 else ("running" if chains else "idle")},
    ]


def _attack_surface(rule_hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counters: Dict[str, int] = {}
    for hit in rule_hits:
        rid = str(hit.get("rule_id") or "")
        prefix = rid.split("-")[1] if "-" in rid and len(rid.split("-")) > 1 else "OTHER"
        counters[prefix] = counters.get(prefix, 0) + int(hit.get("hit_count") or 0)
    rows = [{"surface": key, "count": value} for key, value in counters.items()]
    rows.sort(key=lambda item: item["count"], reverse=True)
    return rows[:8]


def _risk_score(stats: Dict[str, Any], chains: List[Dict[str, Any]], open_chains: List[Dict[str, Any]]) -> int:
    total = max(1, int(stats.get("total") or 0))
    blocked = int(stats.get("blocked") or 0)
    high_risk = int(stats.get("high_risk") or 0)
    max_chain = max((int(chain.get("max_confidence") or 0) for chain in chains), default=0)
    score = round((blocked / total) * 35 + (high_risk / total) * 25 + min(len(open_chains), 10) * 4 + max_chain * 0.25)
    return max(0, min(100, score))


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _mission_summary(stats: Dict[str, Any], risk_score: int, open_count: int, active_rules: int) -> str:
    return (
        f"已接入 {stats.get('total', 0)} 条审计事件，"
        f"累计阻断 {stats.get('blocked', 0)} 次，"
        f"{open_count} 条链路等待闭环，"
        f"{active_rules} 条规则产生过命中，当前风险分 {risk_score}。"
    )


def _next_action(open_chains: List[Dict[str, Any]], rule_hits: List[Dict[str, Any]], stats: Dict[str, Any]) -> str:
    if open_chains:
        chain = open_chains[0]
        return f"优先处理链路 {chain.get('chain_id') or '--'}，查看证据包并登记处置动作。"
    if rule_hits:
        return f"复核高频命中规则 {rule_hits[0].get('rule_id') or '--'}，同步运行规则矩阵自测。"
    if stats.get("total"):
        return "当前链路处于稳定状态，建议启动红队剧本验证回归覆盖。"
    return "先运行攻防链路或工具沙箱，生成第一条可追踪证据链。"


def _limit(value: Any, default: int, lower: int, upper: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(lower, min(number, upper))
