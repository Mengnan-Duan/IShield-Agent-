"""审计日志路由"""
from flask import Blueprint, request, g
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.audit_log import query_audit, get_audit_summary

audit_bp = Blueprint("audit", __name__, url_prefix="/api/audit")


@audit_bp.route("/logs", methods=["GET"])
def get_audit_logs():
    """
    GET /api/audit/logs
    查询参数: token, ip, start, end, action, limit, offset
    """
    token = request.args.get("token")
    ip = request.args.get("ip")
    start = request.args.get("start")
    end = request.args.get("end")
    action = request.args.get("action")
    limit = min(int(request.args.get("limit", 200)), 1000)
    offset = int(request.args.get("offset", 0))

    result = query_audit(token=token, ip=ip, start=start, end=end,
                         action=action, limit=limit, offset=offset)
    return make_response(result)


@audit_bp.route("/summary", methods=["GET"])
def get_audit_summary_route():
    """GET /api/audit/summary — 审计统计摘要"""
    days = int(request.args.get("days", 7))
    result = get_audit_summary(days=days)
    return make_response(result)
