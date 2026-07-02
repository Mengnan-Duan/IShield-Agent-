"""威胁聚合分析服务"""
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.events import get_events_from_db, get_stats

_UTC8 = timezone(timedelta(hours=8))
_CITY_POINTS = [
    ("北京", 39.9042, 116.4074),
    ("上海", 31.2304, 121.4737),
    ("深圳", 22.5431, 114.0579),
    ("香港", 22.3193, 114.1694),
    ("新加坡", 1.3521, 103.8198),
    ("东京", 35.6762, 139.6503),
    ("广州", 23.1291, 113.2644),
    ("杭州", 30.2741, 120.1551),
    ("成都", 30.5728, 104.0668),
    ("武汉", 30.5928, 114.3055),
]


def _local_now():
    return datetime.now(_UTC8)


def _blocked(event: dict) -> bool:
    status = event.get("status", "")
    return "拦截" in status or "阻断" in status


def _classify_event(event: dict) -> str:
    category = (event.get("category") or "").lower()
    detail = (event.get("detail") or "").lower()
    tool_name = (event.get("tool_name") or "").lower()
    event_type = (event.get("type") or "").lower()

    if "prompt" in category or "injection" in category or "检测" in event_type:
        return "Prompt Injection"
    if "policy" in category or "策略" in event_type:
        return "策略违规"
    if tool_name in {"read_file", "write_file"} or "file" in category or "路径" in detail:
        return "文件越界"
    if tool_name == "http_request" or "ssrf" in category or "http" in detail:
        return "SSRF/API 滥用"
    if tool_name == "send_email" or "邮件" in detail:
        return "邮件钓鱼"
    if tool_name:
        return "工具越权"
    if "query" in detail or "数据" in detail:
        return "数据探测"
    return event.get("category") or event.get("type") or "未知威胁"


def _bucket_confidence(score: int) -> str:
    if score <= 20:
        return "0-20"
    if score <= 40:
        return "21-40"
    if score <= 60:
        return "41-60"
    if score <= 80:
        return "61-80"
    return "81-100"


def _geo_from_ip(ip: str):
    if not ip or ip in {"127.0.0.1", "localhost", "::1"}:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        num = sum(int(p) << (8 * i) for i, p in enumerate(reversed(parts)))
        idx = num % len(_CITY_POINTS)
        city, lat, lng = _CITY_POINTS[idx]
        return {"name": city, "lat": lat, "lng": lng}
    except (ValueError, TypeError):
        return None


def get_analytics(days: int = 7) -> dict:
    all_events = get_events_from_db(limit=2000)
    if not all_events:
        return _empty_analytics()

    now = _local_now()
    today_str = now.strftime("%Y-%m-%d")
    today_events = [e for e in all_events if e["time"].startswith(today_str)]
    today_total = len(today_events)
    today_blocked = sum(1 for e in today_events if _blocked(e))
    today_rate = round(today_blocked / today_total * 100, 1) if today_total else 0

    trend_7d = []
    for i in range(days - 1, -1, -1):
        d = now - timedelta(days=i)
        d_str = d.strftime("%Y-%m-%d")
        day_ev = [e for e in all_events if e["time"].startswith(d_str)]
        day_blocked = sum(1 for e in day_ev if _blocked(e))
        trend_7d.append({
            "date": d_str,
            "total": len(day_ev),
            "blocked": day_blocked,
            "passed": len(day_ev) - day_blocked,
            "rate": round(day_blocked / len(day_ev) * 100, 1) if day_ev else 0,
        })

    recent_60m = []
    for i in range(59, -1, -1):
        start = now - timedelta(minutes=i)
        minute_prefix = start.strftime("%Y-%m-%d %H:%M")
        minute_events = [e for e in all_events if e["time"].startswith(minute_prefix)]
        recent_60m.append({
            "time": start.strftime("%H:%M"),
            "total": len(minute_events),
            "blocked": sum(1 for e in minute_events if _blocked(e)),
        })

    type_counter = Counter()
    conf_values = defaultdict(list)
    tool_counter = Counter()
    tool_blocked = Counter()
    confidence_hist = Counter({"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0})
    severity_counter = Counter({"low": 0, "medium": 0, "high": 0, "critical": 0})
    region_counter = Counter()

    for e in all_events:
        threat_type = _classify_event(e)
        type_counter[threat_type] += 1

        conf = int(e.get("confidence") or 0)
        conf_values[threat_type].append(conf)
        confidence_hist[_bucket_confidence(conf)] += 1

        level = (e.get("threat_level") or "low").lower()
        if level not in severity_counter:
            severity_counter[level] = 0
        severity_counter[level] += 1

        tool = e.get("tool_name") or ((e.get("metadata") or {}).get("tool")) or "unknown"
        tool_counter[tool] += 1
        if _blocked(e):
            tool_blocked[tool] += 1

        geo = _geo_from_ip(e.get("source_ip"))
        if geo:
            region_counter[(geo["name"], geo["lat"], geo["lng"])] += 1

    top_threats = []
    for t, count in type_counter.most_common(6):
        values = [v for v in conf_values[t] if v is not None]
        avg_conf = round(sum(values) / len(values), 1) if values else 0
        top_threats.append({"type": t, "count": count, "avg_confidence": avg_conf})

    top_tools = []
    for tool, total in tool_counter.most_common(6):
        blocked = tool_blocked.get(tool, 0)
        top_tools.append({
            "tool": tool,
            "total": total,
            "blocked": blocked,
            "passed": total - blocked,
            "block_rate": round(blocked / total * 100, 1) if total else 0,
        })

    source_regions = [
        {"name": name, "lat": lat, "lng": lng, "value": value}
        for (name, lat, lng), value in region_counter.most_common(20)
    ]

    stats = get_stats()
    high = severity_counter.get("high", 0) + severity_counter.get("critical", 0)
    medium = severity_counter.get("medium", 0)
    total = stats.get("total", 0)
    threat_score = min(100, round(((high * 2 + medium) / max(total, 1)) * 100)) if total else 0

    recommendations = []
    if top_threats:
        recommendations.append(f"近期最常见威胁类型为「{top_threats[0]['type']}」，共 {top_threats[0]['count']} 次。")
    if any(item["avg_confidence"] < 50 for item in top_threats):
        recommendations.append("部分威胁检测置信度偏低，建议继续优化规则和语义判定。")
    if tool_blocked.get("send_email", 0) >= 3:
        recommendations.append("邮件工具拦截次数较高，建议重点核验白名单阻断效果。")
    if not recommendations:
        recommendations.append("当前系统运行平稳，未检测��明显异常。")

    return {
        "today": {"total": today_total, "blocked": today_blocked, "rate": today_rate},
        "trend_7d": trend_7d,
        "trend_60m": recent_60m,
        "top_threats": top_threats,
        "top_tools": top_tools,
        "confidence_distribution": [{"range": k, "count": v} for k, v in confidence_hist.items()],
        "severity_distribution": [{"level": k, "count": v} for k, v in severity_counter.items()],
        "source_regions": source_regions,
        "recommendations": recommendations,
        "threat_score": threat_score,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def get_dashboard_overview() -> dict:
    stats = get_stats()
    analytics = get_analytics(days=7)
    return {
        "kpis": {
            "total": stats.get("total", 0),
            "blocked": stats.get("blocked", 0),
            "passed": stats.get("passed", 0),
            "block_rate": stats.get("block_rate", 0),
            "high_risk": stats.get("high_risk", 0),
            "today_total": stats.get("today_total", 0),
            "today_blocked": stats.get("today_blocked", 0),
            "threat_score": analytics.get("threat_score", 0),
        },
        "trend_7d": analytics.get("trend_7d", []),
        "trend_60m": analytics.get("trend_60m", []),
        "top_threats": analytics.get("top_threats", []),
        "top_tools": analytics.get("top_tools", []),
        "confidence_distribution": analytics.get("confidence_distribution", []),
        "severity_distribution": analytics.get("severity_distribution", []),
        "source_regions": analytics.get("source_regions", []),
        "recommendations": analytics.get("recommendations", []),
        "generated_at": analytics.get("generated_at"),
    }


def _empty_analytics():
    return {
        "today": {"total": 0, "blocked": 0, "rate": 0},
        "trend_7d": [],
        "trend_60m": [],
        "top_threats": [],
        "top_tools": [],
        "confidence_distribution": [
            {"range": "0-20", "count": 0},
            {"range": "21-40", "count": 0},
            {"range": "41-60", "count": 0},
            {"range": "61-80", "count": 0},
            {"range": "81-100", "count": 0},
        ],
        "severity_distribution": [
            {"level": "low", "count": 0},
            {"level": "medium", "count": 0},
            {"level": "high", "count": 0},
            {"level": "critical", "count": 0},
        ],
        "source_regions": [],
        "recommendations": ["暂无数据，等待检测任务执行..."],
        "threat_score": 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
