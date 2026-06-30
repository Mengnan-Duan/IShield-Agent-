"""攻击链关联分析路由"""
from flask import Blueprint, request
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.attack_chain_analyzer import (
    get_attack_chains_summary,
    detect_multi_stage_attack,
    classify_attack_pattern,
)
from services.events import get_chain_events, get_chain_summary

chains_bp = Blueprint("chains", __name__, url_prefix="/api/chains")


@chains_bp.route("", methods=["GET"])
def list_chains():
    """GET /api/chains — 攻击链列表（带 limit）"""
    limit = int(request.args.get("limit", 50))
    chains = get_chain_summary(limit=limit)
    return make_response({"chains": chains, "total": len(chains)})


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

    # 获取链汇总信息（包含 status/source_ip 等）
    summaries = get_chain_summary(limit=1000)
    chain_info = next((s for s in summaries if s.get("chain_id") == chain_id), None)
    if not chain_info:
        chain_info = {"chain_id": chain_id}

    return make_response({
        "chain": chain_info,
        "chain_id": chain_id,
        "events": events,
        "analysis": analysis,
    })
