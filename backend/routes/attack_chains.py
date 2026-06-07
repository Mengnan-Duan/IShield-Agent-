"""攻击链关联分析路由"""
from flask import Blueprint
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.attack_chain_analyzer import (
    get_attack_chains_summary,
    detect_multi_stage_attack,
    classify_attack_pattern,
)
from services.events import get_chain_events

chains_bp = Blueprint("chains", __name__, url_prefix="/api/chains")


@chains_bp.route("/summary", methods=["GET"])
def chains_summary():
    """GET /api/chains/summary — 全局攻击链摘要"""
    result = get_attack_chains_summary()
    return make_response(result)


@chains_bp.route("/<chain_id>", methods=["GET"])
def chain_detail(chain_id: str):
    """GET /api/chains/<chain_id> — 单条攻击链详情"""
    events = get_chain_events(chain_id)
    if not events:
        raise ValidationError(f"未找到 chain_id={chain_id} 的事件")

    analysis = detect_multi_stage_attack(chain_id)
    return make_response({
        "chain_id": chain_id,
        "events": events,
        "analysis": analysis,
    })
