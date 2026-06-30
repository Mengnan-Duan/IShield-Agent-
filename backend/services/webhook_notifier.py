"""Webhook 通知服务 — 高危告警外发到外部系统"""
import json
import time
import threading
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ── Webhook 配置存储 ──────────────────────────────────────────────────────────
_webhooks: List[Dict[str, Any]] = []
_lock = threading.Lock()

# ── 格式化器 ──────────────────────────────────────────────────────────────────
def _format_slack(payload: Dict) -> Dict:
    """Slack Incoming Webhook 格式"""
    alert = payload.get("alert", {})
    severity_colors = {
        "critical": "#dc2626",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#6b7280",
    }
    color = severity_colors.get(str(alert.get("threat_level", "")).lower(), "#6b7280")
    event_type = alert.get("event_type", "未知事件")
    detail = alert.get("detail", "")[:300]
    source_ip = alert.get("source_ip", "未知")
    confidence = alert.get("confidence", 0)
    status = alert.get("status", "未知")
    rule_id = alert.get("rule_id", "-")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 [{severity_colors.get(str(alert.get('threat_level','')).lower(), '🔔').replace('#dc2626','🔴').replace('#f97316','🟠').replace('#eab308','🟡').replace('#6b7280','⚪')}] {event_type}",
                "emoji": True,
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*威胁等级:*\n{alert.get('threat_level', '-')}"},
                {"type": "mrkdwn", "text": f"*可信度:*\n{confidence}%"},
                {"type": "mrkdwn", "text": f"*来源 IP:*\n{source_ip}"},
                {"type": "mrkdwn", "text": f"*规则 ID:*\n{rule_id}"},
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*详情:*\n```{detail}```",
            }
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"状态: {status} | 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"}
            ]
        }
    ]

    return {
        "attachments": [{
            "color": color,
            "blocks": blocks,
        }]
    }


def _format_dingtalk(payload: Dict) -> Dict:
    """钉钉自定义机器人格式"""
    alert = payload.get("alert", {})
    level_map = {"critical": "危险", "high": "高危", "medium": "中危", "low": "低危"}
    level_text = level_map.get(str(alert.get("threat_level", "")).lower(), "未知")

    content = (
        f"## 🔔 IShield 安全告警\n\n"
        f"**威胁等级:** {level_text}\n\n"
        f"**事件类型:** {alert.get('event_type', '未知')}\n\n"
        f"**详情:** {alert.get('detail', '-')[:200]}\n\n"
        f"**来源 IP:** {alert.get('source_ip', '-')}\n\n"
        f"**规则 ID:** {alert.get('rule_id', '-')}\n\n"
        f"**可信度:** {alert.get('confidence', 0)}%\n\n"
        f"**时间:** {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    return {"msgtype": "markdown", "markdown": {"title": "IShield 安全告警", "text": content}}


def _format_generic(payload: Dict) -> Dict:
    """通用 JSON 格式"""
    return {"source": "IShield", "timestamp": time.time(), **payload}


def _get_formatter(fmt: str):
    return {
        "slack": _format_slack,
        "dingtalk": _format_dingtalk,
        "generic": _format_generic,
    }.get(fmt, _format_generic)


# ── 核心通知函数 ───────────────────────────────────────────────────────────────
def fire_webhooks(event_type: str, **kwargs) -> Dict[str, Any]:
    """
    向所有已注册的 Webhook 发送通知。

    参数（与 broadcast_alert 一致）：
      event_type, detail, status, threat_level, confidence,
      source_ip, action, tool_name, target, rule_id, category, metadata

    返回: {"sent": [...], "failed": [...], "total": N}
    """
    severity = kwargs.get("threat_level", "")
    # 只在高危/中危以上触发
    if severity not in {"critical", "high", "medium"}:
        return {"sent": [], "failed": [], "total": 0, "skipped": "low_severity"}

    payload = {"alert": kwargs, "event_type": event_type, "fired_at": time.time()}

    results = {"sent": [], "failed": [], "total": 0}
    with _lock:
        webhooks_snapshot = list(_webhooks)

    for wh in webhooks_snapshot:
        fmt = wh.get("format", "generic")
        formatter = _get_formatter(fmt)
        body = formatter(payload)
        body_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")

        req = Request(
            wh["url"],
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "IShield-Webhook/1.0",
            },
        )
        if wh.get("secret"):
            import hmac, hashlib
            sign = hmac.new(
                wh["secret"].encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()
            req.add_header("X-Webhook-Signature", sign)

        try:
            with urlopen(req, timeout=10) as resp:
                results["sent"].append({
                    "name": wh.get("name", wh["url"]),
                    "status": resp.status,
                })
        except HTTPError as e:
            results["failed"].append({
                "name": wh.get("name", wh["url"]),
                "error": f"HTTP {e.code}: {e.reason}",
            })
        except URLError as e:
            results["failed"].append({
                "name": wh.get("name", wh["url"]),
                "error": str(e.reason),
            })
        except Exception as e:
            results["failed"].append({
                "name": wh.get("name", wh["url"]),
                "error": str(e),
            })

    results["total"] = len(webhooks_snapshot)
    return results


def register_webhook(
    name: str,
    url: str,
    format: str = "generic",
    secret: str = "",
    min_severity: str = "medium",
    enabled: bool = True,
) -> Dict[str, Any]:
    """注册一个新 Webhook"""
    webhook = {
        "name": name,
        "url": url,
        "format": format,
        "secret": secret,
        "min_severity": min_severity,
        "enabled": enabled,
        "registered_at": time.time(),
        "call_count": 0,
    }
    with _lock:
        _webhooks.append(webhook)
    return {"success": True, "name": name, "total": len(_webhooks)}


def unregister_webhook(name: str) -> Dict[str, Any]:
    """按名称注销 Webhook"""
    with _lock:
        before = len(_webhooks)
        _webhooks[:] = [w for w in _webhooks if w.get("name") != name]
        removed = before - len(_webhooks)
    return {"success": removed > 0, "removed": removed}


def list_webhooks() -> List[Dict[str, Any]]:
    """列出所有 Webhook（不含 secret）"""
    with _lock:
        return [
            {k: v for k, v in w.items() if k != "secret"}
            for w in _webhooks
        ]


def get_webhook_stats() -> Dict[str, Any]:
    """Webhook 全局统计"""
    with _lock:
        return {
            "total": len(_webhooks),
            "enabled": sum(1 for w in _webhooks if w.get("enabled")),
            "by_format": _count_by(_webhooks, "format"),
        }


def _count_by(items: List[Dict], key: str) -> Dict[str, int]:
    counts = {}
    for item in items:
        v = item.get(key, "unknown")
        counts[v] = counts.get(v, 0) + 1
    return counts


# ── 预置 Webhook 配置示例（可通过 API 动态注册）────────────────────────────────
DEMO_WEBHOOKS = [
    # {
    #     "name": "演示 Slack",
    #     "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    #     "format": "slack",
    #     "min_severity": "medium",
    # },
    # {
    #     "name": "演示钉钉",
    #     "url": "https://oapi.dingtalk.com/robot/send?access_token=YOUR_TOKEN",
    #     "format": "dingtalk",
    #     "min_severity": "high",
    # },
]
