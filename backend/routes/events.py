"""事件日志 / 统计 / 导出路由"""
from flask import Blueprint, request, jsonify, make_response as flask_response, Response

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response, make_error, Err
from middleware.error_handler import ValidationError

from services.events import (
    get_events_from_db,
    get_stats,
    cleanup_old_events,
)
from services.analytics import get_analytics
import sqlite3, os, re
from urllib.parse import urlparse

events_bp = Blueprint("events", __name__, url_prefix="/api")


@events_bp.route("/events", methods=["GET"])
def get_events():
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    limit = min(limit, 1000)  # 最大 1000 条

    status_filter = request.args.get("status", None)
    type_filter   = request.args.get("type", None)

    events = get_events_from_db(
        limit=limit,
        offset=offset,
        status_filter=status_filter,
        type_filter=type_filter,
    )
    return make_response({"events": events, "count": len(events)})


@events_bp.route("/stats", methods=["GET"])
def stats():
    s = get_stats()
    return make_response(s)


@events_bp.route("/export", methods=["GET"])
def export_events():
    fmt = request.args.get("format", "json")
    date_from = request.args.get("from", None)
    date_to   = request.args.get("to", None)

    if fmt == "csv":
        import csv, io
        events = get_events_from_db(limit=10000, date_from=date_from, date_to=date_to)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["时间", "事件类型", "详情", "处理状态", "威胁等级", "置信度"])
        for ev in events:
            writer.writerow([
                ev.get("time", ""),
                ev.get("type", ""),
                ev.get("detail", ""),
                ev.get("status", ""),
                ev.get("threat_level", ""),
                ev.get("confidence", ""),
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
    """
    威胁聚合分析 — 供前端仪表盘展示。
    """
    days = request.args.get("days", 7, type=int)
    days = min(days, 30)  # 最多 30 天
    data = get_analytics(days=days)
    return make_response(data)


@events_bp.route("/maintenance/cleanup", methods=["POST"])
def maintenance():
    """
    数据清理端点（生产环境建议加认证保护）。
    清理过期缓存 + 旧事件。
    """
    deleted_cache  = __import__("services.events", fromlist=["cleanup_expired_cache"]).cleanup_expired_cache()
    deleted_events = cleanup_old_events(days=30)
    return make_response({
        "deleted_cache":  deleted_cache,
        "deleted_events": deleted_events,
        "message": f"已清理 {deleted_cache} 条过期缓存，{deleted_events} 条旧事件记录",
    })


# ── 攻击来源热力图端点 ────────────────────────────────────────────────────────
_CHINA_IP_CITY = [
    ("北京", 39.9042, 116.4074),
    ("上海", 31.2304, 121.4737),
    ("深圳", 22.5431, 114.0579),
    ("广州", 23.1291, 113.2644),
    ("杭州", 30.2741, 120.1551),
    ("成都", 30.5728, 104.0668),
    ("南京", 32.0603, 118.7969),
    ("武汉", 30.5928, 114.3055),
    ("西安", 34.3416, 108.9398),
    ("重庆", 29.5630, 106.5516),
    ("天津", 39.3434, 117.3616),
    ("苏州", 31.2989, 120.5853),
    ("长沙", 28.2282, 112.9388),
    ("郑州", 34.7466, 113.6253),
    ("沈阳", 41.8057, 123.4328),
    ("青岛", 36.0671, 120.3826),
    ("大连", 38.9140, 121.6147),
    ("厦门", 24.4798, 118.0894),
    ("福州", 26.0753, 119.2965),
    ("昆明", 25.0406, 102.7129),
]

def _ip_to_geo(ip: str) -> tuple:
    """将IP地址映射到中国城市坐标（简化版hash映射）"""
    if not ip or ip in ("127.0.0.1", "localhost", "::1"):
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        num = sum(int(p) << (8 * i) for i, p in enumerate(reversed(parts)))
        idx = num % len(_CHINA_IP_CITY)
        lat, lng = _CHINA_IP_CITY[idx][1], _CHINA_IP_CITY[idx][2]
        jitter = ((num // 256) % 100) / 1000.0
        return (round(lat + jitter, 4), round(lng + jitter, 4))
    except (ValueError, TypeError):
        return None


@events_bp.route("/heatmap", methods=["GET"])
def get_attack_heatmap():
    """返回攻击来源地理分布（用于地图热力图）"""
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ishield.db")
    if not os.path.exists(db_path):
        return make_response({"points": [], "total": 0})

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute(
        "SELECT detail, time FROM events WHERE status IN ('已阻断','已拦截') ORDER BY time DESC LIMIT 500"
    ).fetchall()

    # 从 detail 中提取 IP（简化：从 detail 字符串匹配 IP 模式）
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    geo_points = []
    seen_cities = {}

    for row in rows:
        detail = row["detail"] or ""
        ips = ip_pattern.findall(detail)
        for ip in ips:
            geo = _ip_to_geo(ip)
            if geo:
                city_idx = sum(ord(c) for c in ip) % len(_CHINA_IP_CITY)
                city = _CHINA_IP_CITY[city_idx][0]
                if city not in seen_cities:
                    seen_cities[city] = 0
                seen_cities[city] += 1

    # 聚合成带权重的热力点
    for city, count in seen_cities.items():
        city_info = next((c for c in _CHINA_IP_CITY if c[0] == city), None)
        if city_info:
            geo_points.append({
                "name": city,
                "lat": city_info[1],
                "lng": city_info[2],
                "value": count,
            })

    conn.close()
    geo_points.sort(key=lambda x: x["value"], reverse=True)
    return make_response({"points": geo_points, "total": len(geo_points)})
