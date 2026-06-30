"""行为分析路由 — 异常 IP 报告、行为摘要"""
from flask import Blueprint
from middleware.logger import get_logger
from middleware.error_handler import ValidationError

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response
from services.behavior_analyzer import get_behavior_analyzer
from services.risk_engine import get_risk_engine

logger = get_logger()
behavior_bp = Blueprint("behavior", __name__, url_prefix="/api/behavior")


@behavior_bp.route("/summary", methods=["GET"])
def behavior_summary():
    """GET /api/behavior/summary — 全局异常摘要，Top 20 风险 IP"""
    analyzer = get_behavior_analyzer()
    return make_response(analyzer.get_summary())


@behavior_bp.route("/risk-summary", methods=["GET"])
def risk_summary():
    """GET /api/behavior/risk-summary — 会话/IP/Token 风险闭环摘要"""
    return make_response(get_risk_engine().get_summary())


@behavior_bp.route("/ip/<ip>", methods=["GET"])
def ip_report(ip: str):
    """GET /api/behavior/ip/<ip> — 指定 IP 详细行为报告"""
    analyzer = get_behavior_analyzer()
    report = analyzer.get_ip_report(ip)
    if not report.get("found"):
        raise ValidationError(f"未找到 IP {ip} 的行为数据")
    return make_response(report)


@behavior_bp.route("/status/<ip>", methods=["GET"])
def ip_status(ip: str):
    """GET /api/behavior/status/<ip> — 快速查询 IP 是否被封禁"""
    analyzer = get_behavior_analyzer()
    score = analyzer.get_anomaly_score(ip)
    banned = analyzer.is_banned(ip)
    return make_response({
        "ip": ip,
        "score": score,
        "banned": banned,
        "threat_level": analyzer.get_threat_level(ip),
    })


@behavior_bp.route("/bans", methods=["GET"])
def list_bans():
    """GET /api/behavior/bans — 当前活跃封禁列表"""
    from services.ip_bans import get_active_bans, get_ban_count
    return make_response({
        "bans": get_active_bans(limit=200),
        "stats": get_ban_count(),
    })


@behavior_bp.route("/bans/<ip>", methods=["DELETE"])
def unban_ip(ip: str):
    """DELETE /api/behavior/bans/<ip> — 解封指定 IP"""
    from services.ip_bans import unban_ip as _db_unban
    analyzer = get_behavior_analyzer()
    # 清除内存状态
    with analyzer._lock:
        p = analyzer._profiles.get(ip)
        if p:
            p.is_banned = False
            p.score = max(0, p.score - 20)
    # 清除 DB 记录
    db_ok = _db_unban(ip)
    return make_response({
        "ip": ip,
        "unbanned": db_ok,
        "message": f"IP {ip} 已解封" if db_ok else f"IP {ip} 未在封禁列表中",
    })


@behavior_bp.route("/bans/<ip>", methods=["POST"])
def manual_ban_ip(ip: str):
    """POST /api/behavior/bans/<ip> — 手动封禁指定 IP"""
    from flask import request
    from services.ip_bans import ban_ip
    data = request.get_json(silent=True) or {}
    duration = int(data.get("duration", 300))
    reason = str(data.get("reason", "管理员手动封禁"))
    ban_ip(ip, reason=reason, duration_seconds=duration, score_at_ban=100)
    return make_response({
        "ip": ip,
        "banned": True,
        "duration_seconds": duration,
        "reason": reason,
    })
