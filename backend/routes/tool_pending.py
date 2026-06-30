"""待确认工具调用 API — 查询列表 / 确认放行 / 拒绝 / 统计"""
from flask import Blueprint, request
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.pending_queue import (
    create_pending, get_pending, list_pending, get_pending_count,
    resolve_pending, expire_pending, get_pending_stats,
)

pending_bp = Blueprint("tool_pending", __name__, url_prefix="/api/tool")


@pending_bp.route("/pending", methods=["GET"])
def get_pending_list():
    """查询待确认列表"""
    status = request.args.get("status", "all")
    limit = int(request.args.get("limit", 100))
    expire_pending()
    items = list_pending(limit=limit, status=status)
    stats = get_pending_stats()
    return make_response({
        "items": items,
        "count": len(items),
        "pending": stats["pending"],
        "confirmed": stats["confirmed"],
        "rejected": stats["rejected"],
        "timeout": stats["timeout"],
        **stats,
    })


@pending_bp.route("/pending/<pending_id>", methods=["GET"])
def get_single_pending(pending_id: str):
    """查询单个待确认记录"""
    item = get_pending(pending_id)
    if not item:
        return make_response({"found": False, "pending_id": pending_id})
    return make_response({"found": True, "item": item})


@pending_bp.route("/pending/<pending_id>/confirm", methods=["POST"])
def confirm_pending(pending_id: str):
    """确认放行（confirm）"""
    resolved_by = request.headers.get("X-Admin-Approval-Code") or \
                  request.args.get("resolved_by") or \
                  request.get_json(silent=True).get("resolved_by") if request.is_json else None or "admin"
    record = resolve_pending(pending_id, resolution="confirmed", resolved_by=str(resolved_by))
    if not record:
        raise ValidationError(f"未找到待确认记录: {pending_id}，可能已超时或已被处理")
    return make_response({
        "success": True,
        "pending_id": pending_id,
        "resolution": "confirmed",
        "record": record,
        "message": "已确认放行，可重新调用该工具",
    })


@pending_bp.route("/pending/<pending_id>/reject", methods=["POST"])
def reject_pending(pending_id: str):
    """拒绝（reject）"""
    resolved_by = request.headers.get("X-Admin-Approval-Code") or \
                  request.args.get("resolved_by") or \
                  request.get_json(silent=True).get("resolved_by") if request.is_json else None or "admin"
    record = resolve_pending(pending_id, resolution="rejected", resolved_by=str(resolved_by))
    if not record:
        raise ValidationError(f"未找到待确认记录: {pending_id}，可能已超时或已被处理")
    return make_response({
        "success": True,
        "pending_id": pending_id,
        "resolution": "rejected",
        "record": record,
        "message": "已拒绝该工具调用",
    })


@pending_bp.route("/pending/<pending_id>/execute", methods=["POST"])
def execute_after_confirm(pending_id: str):
    """
    确认后重新执行工具。
    前端：查询 pending 记录 → 用户点击确认 → 调用本接口
    后端：先 resolve_pending("confirmed") → 再调 tool_runner.run_tool()
    """
    record = resolve_pending(pending_id, resolution="confirmed", resolved_by="admin")
    if not record:
        raise ValidationError(f"未找到待确认记录: {pending_id}")

    from tools.tool_runner import run_tool
    from flask import g

    result = run_tool(
        tool_name=record["tool_name"],
        params=record["params"],
        source_ip=record.get("source_ip"),
        action=record.get("action"),
        chain_id=record.get("chain_id"),
        token_meta={"name": record.get("token_name")},
    )
    return make_response({
        "success": True,
        "pending_id": pending_id,
        "tool_result": result,
    })


@pending_bp.route("/pending/stats", methods=["GET"])
def pending_stats():
    """待确认队列统计"""
    return make_response(get_pending_stats())


@pending_bp.route("/pending/expire", methods=["POST"])
def manual_expire():
    """手动触发超时清理"""
    count = expire_pending()
    return make_response({"expired": count})
