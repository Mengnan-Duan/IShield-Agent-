"""行为守卫中间件 — 在 rate_limiter 之后，对异常 IP 自动封禁"""
from flask import request, g
from services.behavior_analyzer import get_behavior_analyzer
from services.risk_engine import get_risk_engine
from middleware.logger import get_logger

logger = get_logger()


def setup_behavior_guard(app):
    """注册 before_request 钩子"""

    @app.before_request
    def check_behavior_guard():
        if not request.path.startswith("/api/"):
            return None

        ip = _get_client_ip()
        analyzer = get_behavior_analyzer()
        risk_engine = get_risk_engine()

        if analyzer.is_banned(ip):
            logger.warning(f"[BehaviorGuard] Rejected banned IP {ip} -> {request.path}")
            from flask import jsonify
            return jsonify({
                "code": "FORBIDDEN",
                "success": False,
                "message": f"IP {ip} has been temporarily blocked due to suspicious activity.",
                "retry_after": 300,
            }), 429

        g._client_ip = ip
        g._behavior_analyzer = analyzer
        g._risk_engine = risk_engine
        high_risk_prefixes = ("/api/redteam", "/api/campaigns", "/api/batch", "/api/simulate")
        g._count_for_behavior = request.path.startswith(high_risk_prefixes)
        return None

    @app.after_request
    def log_behavior(response):
        ip = getattr(g, "_client_ip", None)
        if ip is None or not hasattr(g, "_behavior_analyzer"):
            return response

        try:
            analyzer = g._behavior_analyzer
            result = "malicious" if (response.status_code >= 400 or getattr(g, "_threat_detected", False)) else "safe"
            if getattr(g, "_count_for_behavior", False):
                analyzer.track_request(
                    ip=ip,
                    endpoint=request.path,
                    result=result,
                    threat_level=getattr(g, "_threat_level", "low"),
                )
                token_name = ((getattr(g, "token_meta", None) or {}).get("name"))
                session_id = getattr(g, "_fingerprint", None)
                severity_score = 0 if result == "safe" else 25
                severity_score += 10 if request.path.startswith("/api/simulate") else 0
                risk_report = g._risk_engine.record(
                    ip=ip,
                    token=token_name,
                    session=session_id,
                    score=severity_score,
                    reason=f"{request.path}:{result}",
                    source="behavior_guard",
                )
                g._risk_action = risk_report.get("action", "allow")
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
