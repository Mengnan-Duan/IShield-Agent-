"""行为守卫中间件 — 在 rate_limiter 之后，对异常 IP 自动封禁"""
from flask import request, g
from services.behavior_analyzer import get_behavior_analyzer
from middleware.logger import get_logger
import time

logger = get_logger()


def setup_behavior_guard(app):
    """注册 before_request 钩子"""

    @app.before_request
    def check_behavior_guard():
        # 只拦截 API 请求
        if not request.path.startswith("/api/"):
            return None

        ip = _get_client_ip()
        analyzer = get_behavior_analyzer()

        # 检查是否被封禁
        if analyzer.is_banned(ip):
            logger.warning(f"[BehaviorGuard] Rejected banned IP {ip} -> {request.path}")
            from flask import jsonify
            return jsonify({
                "code": "FORBIDDEN",
                "success": False,
                "message": f"IP {ip} has been temporarily blocked due to suspicious activity.",
                "retry_after": 300,
            }), 429

        # 记录请求（事后分析），只对高危端点计入行为异常分
        g._client_ip = ip
        g._behavior_analyzer = analyzer
        # detect/simulate/audit/audit-logs 等日常端点不计入异常分
        high_risk_prefixes = ("/api/redteam", "/api/campaigns", "/api/batch")
        g._count_for_behavior = request.path.startswith(high_risk_prefixes)
        return None

    @app.after_request
    def log_behavior(response):
        """请求结束后记录行为"""
        ip = getattr(g, "_client_ip", None)
        if ip is None or not hasattr(g, "_behavior_analyzer"):
            return response

        try:
            analyzer = g._behavior_analyzer
            result = "malicious" if (response.status_code == 200 and
                                     getattr(g, "_threat_detected", False)) else "safe"

            # 只有高危端点才计入行为异常分（避免误封日常操作）
            if getattr(g, "_count_for_behavior", False):
                analyzer.track_request(
                    ip=ip,
                    endpoint=request.path,
                    result=result,
                    threat_level=getattr(g, "_threat_level", "low"),
                )
        except Exception:
            pass
        return response


def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    demo = request.headers.get("X-Demo-Source-IP", "").strip()
    if demo:
        return demo.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


def _normalize_endpoint(path: str) -> str:
    """将 /api/campaigns/abc123 -> /api/campaigns"""
    parts = path.split("/")
    # /api/behavior/ip/1.2.3.4 -> /api/behavior
    if len(parts) >= 3 and parts[2] == "behavior":
        return "/".join(parts[:3])
    if len(parts) >= 4 and parts[2] in ("campaigns", "chains", "events"):
        return "/".join(parts[:3])
    if len(parts) >= 3:
        return "/".join(parts[:3])
    return path
