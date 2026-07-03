"""Remediation planning and closure APIs."""
import os
import sys

from flask import Blueprint, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from services.events import get_chain_events, get_chain_summary
from services.evidence import build_evidence_packet
from services.pending_queue import list_pending, expire_pending
from services.remediation import (
    build_remediation_plan,
    list_remediation_actions,
    record_remediation_action,
)
from utils.response import make_response


remediation_bp = Blueprint("remediation", __name__, url_prefix="/api/remediation")


@remediation_bp.route("/chain/<chain_id>", methods=["GET"])
def chain_remediation(chain_id: str):
    events = get_chain_events(chain_id)
    if not events:
        raise ValidationError(f"未找到攻击链: {chain_id}")

    expire_pending()
    pending_items = [item for item in list_pending(status="all", limit=200) if item.get("chain_id") == chain_id]
    action_records = list_remediation_actions(chain_id=chain_id, limit=100)
    packet = build_evidence_packet(events, chain_id)
    plan = build_remediation_plan(packet, pending_items=pending_items, action_records=action_records)
    return make_response({
        "chain_id": chain_id,
        "evidence_packet": packet,
        "remediation": plan,
        "pending_items": pending_items,
        "action_records": action_records,
    }, chain_id=chain_id)


@remediation_bp.route("/action", methods=["POST"])
def remediation_action():
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")
    data = request.get_json(silent=True) or {}
    chain_id = str(data.get("chain_id", "")).strip()
    action_id = str(data.get("action_id", "")).strip()
    if not chain_id:
        raise ValidationError("chain_id 不能为空")
    if not action_id:
        raise ValidationError("action_id 不能为空")

    try:
        record = record_remediation_action(
            chain_id=chain_id,
            action_id=action_id,
            disposition=str(data.get("disposition") or "completed"),
            operator=str(data.get("operator") or "operator"),
            note=str(data.get("note") or ""),
        )
    except ValueError as exc:
        raise ValidationError(str(exc))

    events = get_chain_events(chain_id)
    packet = build_evidence_packet(events, chain_id) if events else {"chain_id": chain_id}
    pending_items = [item for item in list_pending(status="all", limit=200) if item.get("chain_id") == chain_id]
    action_records = list_remediation_actions(chain_id=chain_id, limit=100)
    plan = build_remediation_plan(packet, pending_items=pending_items, action_records=action_records)
    return make_response({
        "recorded": True,
        "record": record,
        "remediation": plan,
    }, chain_id=chain_id)


@remediation_bp.route("/summary", methods=["GET"])
def remediation_summary():
    chains = get_chain_summary(limit=int(request.args.get("limit", 20)))
    items = []
    for chain in chains:
        packet = chain.get("evidence_packet") or {}
        records = list_remediation_actions(chain_id=chain.get("chain_id"), limit=100)
        plan = build_remediation_plan(packet, action_records=records)
        items.append({
            "chain_id": chain.get("chain_id"),
            "status_code": chain.get("status_code"),
            "risk_score": chain.get("max_confidence"),
            "remediation": plan,
        })
    open_count = sum(1 for item in items if (item.get("remediation") or {}).get("state") == "open")
    closed_count = sum(1 for item in items if (item.get("remediation") or {}).get("state") == "closed")
    return make_response({
        "items": items,
        "open": open_count,
        "closed": closed_count,
        "total": len(items),
    })
