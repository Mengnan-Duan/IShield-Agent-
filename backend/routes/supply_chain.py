"""供应链安全路由 — Phase 4"""
from flask import Blueprint
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response
from services.supply_chain_guard import get_supply_chain_guard

supply_bp = Blueprint("supply_chain", __name__, url_prefix="/api/supply")


@supply_bp.route("/summary", methods=["GET"])
def supply_summary():
    """GET /api/supply/summary — 供应链审计摘要"""
    guard = get_supply_chain_guard()
    return make_response(guard.get_summary())


@supply_bp.route("/suspicious", methods=["GET"])
def supply_suspicious():
    """GET /api/supply/suspicious — 可疑域名列表"""
    guard = get_supply_chain_guard()
    return make_response({"domains": guard.get_all_suspicious()})


@supply_bp.route("/domain/<domain>", methods=["GET"])
def supply_domain(domain: str):
    """GET /api/supply/domain/<domain> — 域名详情"""
    guard = get_supply_chain_guard()
    report = guard.get_domain_report(domain)
    return make_response(report)


@supply_bp.route("/trust-tiers", methods=["GET"])
def supply_trust_tiers():
    """GET /api/supply/trust-tiers — 域名信任分层说明"""
    return make_response({
        "tiers": [
            {"level": "allow", "desc": "白名单可信域名，可直接访问"},
            {"level": "observe", "desc": "已知外部域名，允许访问但持续审计"},
            {"level": "challenge", "desc": "陌生或中风险域名，需要确认"},
            {"level": "block", "desc": "高风险域名或存在数据外泄意图，直接阻断"},
        ]
    })
