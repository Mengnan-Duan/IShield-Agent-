"""Closure summary API for rule-hit, evidence, remediation and regression flow."""
import os
import sys

from flask import Blueprint, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.events import get_chain_summary, get_rule_hit_summary, get_stats
from services.remediation import build_remediation_plan, list_remediation_actions
from utils.response import make_response


closure_bp = Blueprint("closure", __name__, url_prefix="/api/closure")


def _limit(value, default=50, lower=1, upper=200):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(lower, min(number, upper))


@closure_bp.route("/summary", methods=["GET"])
def closure_summary():
    limit = _limit(request.args.get("limit"), default=50)
    stats = get_stats()
    chains = get_chain_summary(limit=limit)
    rule_hits = get_rule_hit_summary(limit=5000, per_rule_limit=3)

    chain_items = []
    open_count = 0
    closed_count = 0
    action_record_count = 0
    for chain in chains:
        chain_id = chain.get("chain_id")
        packet = chain.get("evidence_packet") or {}
        records = list_remediation_actions(chain_id=chain_id, limit=100) if chain_id else []
        plan = build_remediation_plan(packet, action_records=records)
        action_record_count += len(records)
        state = plan.get("state")
        if state == "closed":
            closed_count += 1
        elif state == "open":
            open_count += 1
        chain_items.append({
            "chain_id": chain_id,
            "status_code": chain.get("status_code"),
            "status_label": chain.get("status_label"),
            "risk_score": chain.get("max_confidence"),
            "rule_id": ((packet.get("policy_evidence") or {}).get("rule_id") or (packet.get("actors") or {}).get("rule_id")),
            "tool": chain.get("tool_name") or chain.get("action"),
            "target": chain.get("target"),
            "last_seen": chain.get("last_seen") or chain.get("ended_at"),
            "remediation": {
                "state": state,
                "state_label": plan.get("state_label"),
                "progress": plan.get("progress"),
                "next_action": plan.get("next_action"),
            },
        })

    sampled = len(chain_items)
    closure_rate = round((closed_count / sampled) * 100, 1) if sampled else 0.0
    rule_hit_count = sum(int(item.get("hit_count") or 0) for item in rule_hits)
    blocked_rule_hits = sum(int(item.get("blocked_count") or 0) for item in rule_hits)
    active_rule_count = sum(1 for item in rule_hits if int(item.get("hit_count") or 0) > 0)

    if open_count:
        next_action = "优先处理待闭环攻击链，打开最高风险证据链并登记处置动作。"
    elif sampled:
        next_action = "当前抽样链路已完成闭环，可继续运行规则矩阵自测和红队回归复测。"
    else:
        next_action = "运行检测、工具沙箱或联动验证后，系统会自动生成闭环统计。"

    return make_response({
        "version": "v4.9",
        "kpis": {
            "total_events": stats.get("total", 0),
            "today_events": stats.get("today_total", 0),
            "blocked_events": stats.get("blocked", 0),
            "today_blocked": stats.get("today_blocked", 0),
            "chain_total": stats.get("chain_total", 0),
            "chain_sampled": sampled,
            "open_chains": open_count,
            "closed_chains": closed_count,
            "closure_rate": closure_rate,
            "rule_hit_rules": active_rule_count,
            "rule_hit_count": rule_hit_count,
            "blocked_rule_hits": blocked_rule_hits,
            "remediation_records": action_record_count,
        },
        "next_action": next_action,
        "chains": chain_items[:10],
        "rule_hits": rule_hits[:10],
    })
