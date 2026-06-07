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
