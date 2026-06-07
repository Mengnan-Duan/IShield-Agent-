"""事件日志 / 统计 / 导出路由"""
from flask import Blueprint, request, Response

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response
from middleware.error_handler import ValidationError
from services.events import (
    get_events_from_db,
    get_stats,
    cleanup_old_events,
    get_event_detail,
    get_chain_events,
    get_chain_summary,
)
from services.analytics import get_analytics, get_dashboard_overview

events_bp = Blueprint("events", __name__, url_prefix="/api")


@events_bp.route("/events", methods=["GET"])
def get_events():
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    limit = min(limit, 1000)

    status_filter = request.args.get("status", None)
    type_filter = request.args.get("type", None)
    chain_id = request.args.get("chain_id", None)

    events = get_events_from_db(
        limit=limit,
        offset=offset,
        status_filter=status_filter,
        type_filter=type_filter,
        chain_id=chain_id,
    )
    return make_response({"events": events, "count": len(events)})


@events_bp.route("/events/<int:event_id>", methods=["GET"])
def event_detail(event_id: int):
    event = get_event_detail(event_id)
    if not event:
        raise ValidationError(f"未找到事件: {event_id}")

    related_chain = get_chain_events(event.get("chain_id")) if event.get("chain_id") else []
    return make_response({
        "event": event,
        "chain": related_chain,
        "chain_count": len(related_chain),
    })


@events_bp.route("/chains", methods=["GET"])
def chains():
    limit = request.args.get("limit", 50, type=int)
    limit = min(limit, 200)
    summaries = get_chain_summary(limit=limit)
    return make_response({"chains": summaries, "count": len(summaries)})


@events_bp.route("/chains/<chain_id>", methods=["GET"])
def chain_detail(chain_id: str):
    chain_events = get_chain_events(chain_id)
    if not chain_events:
        raise ValidationError(f"未找到攻击链: {chain_id}")

    primary = chain_events[0]
    return make_response({
        "chain_id": chain_id,
        "status": "已阻断" if any("阻断" in (e.get("status") or "") or "拦截" in (e.get("status") or "") for e in chain_events) else "已放行",
        "source_ip": primary.get("source_ip"),
        "action": primary.get("action"),
        "tool_name": primary.get("tool_name"),
        "target": primary.get("target"),
        "events": chain_events,
        "count": len(chain_events),
    })


@events_bp.route("/stats", methods=["GET"])
def stats():
    return make_response(get_stats())


@events_bp.route("/export", methods=["GET"])
def export_events():
    fmt = request.args.get("format", "json")
    date_from = request.args.get("from", None)
    date_to = request.args.get("to", None)

    if fmt == "csv":
        import csv, io
        events = get_events_from_db(limit=10000, date_from=date_from, date_to=date_to)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "时间", "事件类型", "处理状态", "阶段", "攻击链ID", "详情", "威胁等级", "置信度", "来源IP", "工具", "目标"])
        for ev in events:
            writer.writerow([
                ev.get("id", ""),
                ev.get("time", ""),
                ev.get("type", ""),
                ev.get("status", ""),
                ev.get("stage", ""),
                ev.get("chain_id", ""),
                ev.get("detail", ""),
                ev.get("threat_level", ""),
                ev.get("confidence", ""),
                ev.get("source_ip", ""),
                ev.get("tool_name", ""),
                ev.get("target", ""),
            ])
        output.seek(0)
        csv_bytes = "\ufeff" + output.getvalue()
        return Response(
            csv_bytes,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=ishield_events.csv"},
        )

    if fmt == "json":
        events = get_events_from_db(limit=10000, date_from=date_from, date_to=date_to)
        return make_response({"events": events})

    raise ValidationError(f"不支持的导出格式: {fmt}")


@events_bp.route("/analytics", methods=["GET"])
def analytics():
    days = request.args.get("days", 7, type=int)
    days = min(days, 30)
    return make_response(get_analytics(days=days))


@events_bp.route("/dashboard/overview", methods=["GET"])
def dashboard_overview():
    return make_response(get_dashboard_overview())


@events_bp.route("/dashboard/live", methods=["GET"])
def dashboard_live():
    limit = request.args.get("limit", 30, type=int)
    limit = min(limit, 100)
    events = get_events_from_db(limit=limit)
    live_events = [
        {
            "id": e.get("id"),
            "time": e.get("time"),
            "type": e.get("type"),
            "status": e.get("status"),
            "detail": e.get("detail"),
            "threat_level": e.get("threat_level"),
            "confidence": e.get("confidence"),
            "source_ip": e.get("source_ip"),
            "action": e.get("action"),
            "tool_name": e.get("tool_name"),
            "target": e.get("target"),
            "rule_id": e.get("rule_id"),
            "category": e.get("category"),
            "metadata": e.get("metadata"),
            "chain_id": e.get("chain_id"),
            "stage": e.get("stage"),
        }
        for e in events[:limit]
    ]
    return make_response({"events": live_events, "count": len(live_events)})


@events_bp.route("/heatmap", methods=["GET"])
def get_attack_heatmap():
    overview = get_dashboard_overview()
    points = overview.get("source_regions", [])
    return make_response({"points": points, "total": len(points)})


@events_bp.route("/maintenance/cleanup", methods=["POST"])
def maintenance():
    deleted_cache = __import__("services.events", fromlist=["cleanup_expired_cache"]).cleanup_expired_cache()
    deleted_events = cleanup_old_events(days=30)
    return make_response({
        "deleted_cache": deleted_cache,
        "deleted_events": deleted_events,
        "message": f"已清理 {deleted_cache} 条过期缓存，{deleted_events} 条旧事件记录",
    })
