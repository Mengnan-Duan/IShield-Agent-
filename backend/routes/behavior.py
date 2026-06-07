"""行为分析路由 — 异常 IP 报告、行为摘要"""
from flask import Blueprint, g, jsonify
from middleware.logger import get_logger
from middleware.error_handler import ValidationError

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response
from services.behavior_analyzer import get_behavior_analyzer

logger = get_logger()
behavior_bp = Blueprint("behavior", __name__, url_prefix="/api/behavior")


@behavior_bp.route("/summary", methods=["GET"])
def behavior_summary():
    """GET /api/behavior/summary — 全局异常摘要，Top 20 风险 IP"""
    analyzer = get_behavior_analyzer()
    return make_response(analyzer.get_summary())


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
