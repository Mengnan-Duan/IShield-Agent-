"""威胁聚合分析服务"""
from collections import Counter
from datetime import datetime, timezone, timedelta

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.events import get_events_from_db

_UTC8 = timezone(timedelta(hours=8))

def _local_now():
    return datetime.now(_UTC8)


def get_analytics(days: int = 7) -> dict:
    """
    生成威胁聚合分析数据。
    """
    all_events = get_events_from_db(limit=1000)
    if not all_events:
        return _empty_analytics()

    now = _local_now()

    # ── 今日统计 ─────────────────────────────────────────────────
    today_str = now.strftime("%Y-%m-%d")
    today_events = [e for e in all_events if e["time"].startswith(today_str)]
    today_total   = len(today_events)
    today_blocked = sum(1 for e in today_events
                       if "拦截" in e.get("status", "") or "阻断" in e.get("status", ""))
    today_rate    = round(today_blocked / today_total * 100, 1) if today_total else 0

    # ── 7 天趋势 ─────────────────────────────────────────────────
    trend_7d = []
    for i in range(days - 1, -1, -1):
        d = now - timedelta(days=i)
        d_str = d.strftime("%Y-%m-%d")
        day_ev = [e for e in all_events if e["time"].startswith(d_str)]
        day_blocked = sum(1 for e in day_ev
                         if "拦截" in e.get("status", "") or "阻断" in e.get("status", ""))
        trend_7d.append({
            "date":    d_str,
            "total":   len(day_ev),
            "blocked": day_blocked,
            "rate":    round(day_blocked / len(day_ev) * 100, 1) if day_ev else 0,
        })

    # ── 高威胁类型排行 ─────────────────────────────────────────────
    type_counter = Counter()
    conf_values  = {}
    for e in all_events:
        if "拦截" in e.get("status", "") or "阻断" in e.get("status", ""):
            detail = e.get("detail", "")
            # 从 detail 中提取事件类型
            if "检测" in e.get("type", ""):
                type_name = "直接注入"
            elif "沙箱" in detail or "沙箱" in e.get("type", ""):
                type_name = "工具调用"
            elif "策略" in e.get("type", ""):
                type_name = "策略拦截"
            else:
                type_name = e.get("type", "未知")
            type_counter[type_name] += 1

            # 置信度
            conf = e.get("confidence")
            if conf:
                if type_name not in conf_values:
                    conf_values[type_name] = []
                conf_values[type_name].append(conf)

    top_threats = []
    for t, count in type_counter.most_common(5):
        avg_conf = round(sum(conf_values[t]) / len(conf_values[t]), 1) if t in conf_values else 0
        top_threats.append({"type": t, "count": count, "avg_confidence": avg_conf})

    # ── 工具被攻击排行 ─────────────────────────────────────────────
    tool_counter = Counter()
    tool_blocked = Counter()
    for e in all_events:
        detail = e.get("detail", "")
        if "工具=" in detail:
            tool = detail.split("工具=")[1].split(",")[0]
            tool_counter[tool] += 1
            if "拦截" in e.get("status", "") or "阻断" in e.get("status", ""):
                tool_blocked[tool] += 1

    top_tools = []
    for tool, total in tool_counter.most_common(5):
        blocked = tool_blocked.get(tool, 0)
        top_tools.append({
            "tool":    tool,
            "total":   total,
            "blocked": blocked,
            "passed":  total - blocked,
            "block_rate": round(blocked / total * 100, 1) if total else 0,
        })

    # ── 建议 ─────────────────────────────────────────────────────
    recommendations = []
    if top_threats and top_threats[0]["count"] >= 5:
        recommendations.append(f"近期最常见威胁类型为「{top_threats[0]['type']}」，共 {top_threats[0]['count']} 次，建议加强该类攻击的检测规则。")
    if any(t["avg_confidence"] < 50 for t in top_threats):
        recommendations.append("部分威胁检测置信度偏低，建议审查当前规则库是否存在误报或漏报。")
    if tool_blocked.get("send_email", 0) >= 3:
        recommendations.append("邮件工具调用被拦截次数较多，建议审查是否有恶意用户在尝试钓鱼邮件攻击。")
    if not recommendations:
        recommendations.append("当前系统运行平稳，未检测到明显异常。继续保持监控。")

    return {
        "today": {
            "total":   today_total,
            "blocked": today_blocked,
            "rate":    today_rate,
        },
        "trend_7d": trend_7d,
        "top_threats":   top_threats,
        "top_tools":     top_tools,
        "recommendations": recommendations,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _empty_analytics():
    return {
        "today":   {"total": 0, "blocked": 0, "rate": 0},
        "trend_7d": [],
        "top_threats":  [],
        "top_tools":     [],
        "recommendations": ["暂无数据，等待检测任务执行..."],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
