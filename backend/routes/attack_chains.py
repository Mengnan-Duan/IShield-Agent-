"""Attack-chain routes with v4.8 evidence packets."""
from flask import Blueprint, request
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.attack_chain_analyzer import get_attack_chains_summary, detect_multi_stage_attack
from services.events import get_chain_events, get_chain_summary
from services.evidence import build_evidence_packet, status_label, stage_label


chains_bp = Blueprint("chains", __name__, url_prefix="/api/chains")


@chains_bp.route("", methods=["GET"])
def list_chains():
    """GET /api/chains - attack-chain list."""
    limit = int(request.args.get("limit", 50))
    chains = get_chain_summary(limit=limit)
    return make_response({"chains": chains, "total": len(chains)})


@chains_bp.route("/summary", methods=["GET"])
def chains_summary():
    """GET /api/chains/summary - global attack-chain summary."""
    result = get_attack_chains_summary()
    return make_response(result)


@chains_bp.route("/<chain_id>", methods=["GET"])
def chain_detail(chain_id: str):
    """GET /api/chains/<chain_id> - attack-chain detail."""
    events = get_chain_events(chain_id)
    if not events:
        raise ValidationError(f"未找到 chain_id={chain_id} 的事件")

    analysis = detect_multi_stage_attack(chain_id)
    summaries = get_chain_summary(limit=1000)
    chain_info = next((s for s in summaries if s.get("chain_id") == chain_id), None) or {"chain_id": chain_id}
    evidence_packet = build_evidence_packet(events, chain_id)

    return make_response({
        "chain": chain_info,
        "chain_id": chain_id,
        "events": events,
        "analysis": analysis,
        "evidence_packet": evidence_packet,
    })


@chains_bp.route("/<chain_id>/replay", methods=["GET"])
def chain_replay(chain_id: str):
    """GET /api/chains/<chain_id>/replay - normalized runtime replay for UI."""
    events = get_chain_events(chain_id)
    if not events:
        raise ValidationError(f"未找到 chain_id={chain_id} 的事件")

    replay = build_chain_replay(chain_id, events)
    return make_response(replay, chain_id=chain_id)


def build_chain_replay(chain_id: str, events: list) -> dict:
    evidence_packet = build_evidence_packet(events, chain_id)
    verdict = evidence_packet.get("verdict", {})
    actors = evidence_packet.get("actors", {})
    timeline = evidence_packet.get("timeline", [])
    decision = verdict.get("status_code") or "unknown"
    risk_assessment = evidence_packet.get("risk_assessment")

    return {
        "chain_id": chain_id,
        "decision": decision,
        "status": verdict.get("status_label") or status_label(decision),
        "status_code": decision,
        "blocked_at": verdict.get("blocked_at") or "unknown",
        "blocked_at_label": verdict.get("blocked_at_label"),
        "risk_score": verdict.get("risk_score") or 0,
        "risk_level": verdict.get("risk_level") or "unknown",
        "risk_label": verdict.get("risk_label"),
        "source_ip": actors.get("source_ip"),
        "action": actors.get("tool"),
        "tool_name": actors.get("tool"),
        "target": actors.get("target"),
        "summary": verdict.get("summary") or "攻击链已完成运行时审计。",
        "recommendation": verdict.get("recommendation") or "保留审计证据并持续监控相同来源。",
        "risk_assessment": risk_assessment,
        "risk_factors": evidence_packet.get("risk_factors", []),
        "flow": _flow_from_timeline(timeline, decision),
        "runtime_steps": timeline,
        "tool_evidence": evidence_packet.get("tool_evidence"),
        "policy_evidence": evidence_packet.get("policy_evidence"),
        "evidence_packet": evidence_packet,
        "remediation": evidence_packet.get("remediation"),
        "events": events,
        "event_count": len(events),
        "conclusion_event_id": evidence_packet.get("event_id"),
    }


def _flow_from_timeline(timeline: list, decision: str) -> list:
    if not timeline:
        return []

    flow = []
    for idx, item in enumerate(timeline):
        status = item.get("status_code") or "unknown"
        flow.append({
            "key": item.get("stage") or f"stage-{idx + 1}",
            "stage": item.get("stage") or "runtime",
            "title": item.get("title") or item.get("stage_label") or stage_label(item.get("stage")),
            "status": status,
            "status_label": item.get("status_label") or status_label(status),
            "detail": item.get("detail") or "该阶段已完成审计。",
            "risk_score": item.get("risk_score") or 0,
            "highlight": status in {"blocked", "confirm", "error"} or (idx == len(timeline) - 1 and decision in {"blocked", "confirm", "error"}),
        })
    return flow
