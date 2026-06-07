"""API Key / Bearer Token 认证中间件 — 集成审计日志、Token 管理、Per-token 限流、会话指纹"""
import hashlib
import hmac
import time as _time
from functools import wraps
from flask import request, g, jsonify

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import config
from services import audit_log
from services.token_manager import validate_token as tm_validate_token
from services.token_rate_limiter import get_token_rate_limiter
from services.session_fingerprint import get_session_fingerprinter
from services.behavior_analyzer import get_behavior_analyzer

_AUTH_WHITELIST = {"/", "/api/health", "/favicon.ico", "/dashboard"}


def _get_token_from_request() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def _split_token(token: str) -> tuple[str, str]:
    if ":" in token:
        name, sig = token.split(":", 1)
        return name, sig
    return token, ""


def _validate_token(token: str, client_ip: str) -> dict | None:
    """
    完整验证：
    1. 优先走 token_manager（registry、过期、吊销、IP 白名单）
    2. 降级到 config 中的明文 token
    """
    name, sig = _split_token(token)

    # 尝试 token_manager
    if name:
        ok, reason = tm_validate_token(name, token, client_ip)
        if ok:
            return {"name": name, "role": _infer_role(name), "readonly": _is_readonly_name(name)}

    # 降级：config 中的明文 token
    plain_tokens = getattr(config, "API_TOKENS_PLAIN", [])
    if token in plain_tokens:
        return {"name": token, "role": "admin", "readonly": False}

    return None


def _infer_role(name: str) -> str:
    n = name.lower()
    if "admin" in n: return "admin"
    if "operator" in n: return "operator"
    if "analyst" in n: return "analyst"
    if "readonly" in n or "read" in n: return "readonly"
    return "guest"


def _is_readonly_name(name: str) -> bool:
    n = name.lower()
    return "readonly" in n or "read" in n


def _is_write_endpoint(method: str, path: str) -> bool:
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    safe = {
        "/api/health", "/api/events", "/api/behavior", "/api/compliance",
        "/api/stats", "/api/analytics", "/api/dashboard", "/api/policies",
        "/api/samples/stats", "/api/samples/categories", "/api/audit",
        "/api/chains", "/api/tokens/list",
    }
    return not any(path.startswith(p) for p in safe)


def _get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    demo = request.headers.get("X-Demo-Source-IP", "").strip()
    if demo:
        return demo.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


def _norm_endpoint(path: str) -> str:
    parts = path.split("/")
    if len(parts) >= 3:
        return "/".join(parts[:3])
    return path


def setup_auth(app):
    """注册 before_request + after_request 认证钩子"""

    @app.before_request
    def authenticate():
        if request.method == "OPTIONS":
            return None

        path = request.path
        if path in _AUTH_WHITELIST or path.startswith("/dashboard"):
            return None

        client_ip = _get_client_ip()
        g._client_ip = client_ip

        # 会话指纹（在认证前就做）
        fingerprinter = get_session_fingerprinter()
        fingerprint = fingerprinter.fingerprint_request(request)
        g._fingerprint = fingerprint
        g._session = fingerprinter.get_or_create_session(fingerprint)

        # 认证
        if not getattr(config, "AUTH_ENABLED", False):
            g.token_meta = {"name": "anonymous", "role": "guest", "readonly": False}
        else:
            token = _get_token_from_request()
            if not token:
                return jsonify({
                    "code": "UNAUTHORIZED",
                    "success": False,
                    "message": "Missing Authorization header. Use: Authorization: Bearer <token>",
                }), 401

            meta = _validate_token(token, client_ip)
            if not meta:
                return jsonify({
                    "code": "UNAUTHORIZED",
                    "success": False,
                    "message": "Invalid token.",
                }), 401

            if meta["readonly"] and _is_write_endpoint(request.method, path):
                return jsonify({
                    "code": "FORBIDDEN",
                    "success": False,
                    "message": f"Token '{meta['name']}' is read-only.",
                }), 403

            g.token_meta = meta

        # Per-token 限流（认证后立即检查）
        meta = g.token_meta
        limiter = get_token_rate_limiter()
        allowed, count, limit = limiter.check(meta["name"], meta.get("role", "guest"))
        g._token_rate_count = count
        if not allowed:
            audit_log.log_operation(
                meta, request, {"status_code": 429},
                0, threat_level="medium",
                action_tag="rate_limited",
                detail=f"Token rate limit exceeded ({count}/{limit})",
            )
            return jsonify({
                "code": "RATE_LIMITED",
                "success": False,
                "message": f"Token rate limit exceeded ({count}/{limit})",
                "retry_after": 60,
            }), 429

        g._start_time = _time.time()

    @app.after_request
    def audit_and_track(response):
        meta = getattr(g, "token_meta", None)
        client_ip = getattr(g, "_client_ip", "127.0.0.1")
        fingerprint = getattr(g, "_fingerprint", None)
        elapsed = (_time.time() - getattr(g, "_start_time", _time.time())) * 1000

        if meta:
            try:
                # 审计日志（冷启动时 DB 锁竞争可能失败，不影响业务响应）
                audit_log.log_operation(
                    meta, request, response, elapsed,
                    threat_level=_threat_from_status(response.status_code),
                    action_tag=_action_tag(request.path, response.status_code),
                )
            except Exception:
                pass

            # 会话指纹追踪
            if fingerprint:
                try:
                    fp = get_session_fingerprinter()
                    tool = _extract_tool(request.path)
                    result = "malicious" if response.status_code >= 400 else "safe"
                    fp.track_request(fingerprint, client_ip, request.path, result, tool)
                except Exception:
                    pass

            # 行为分析
            try:
                if response.status_code >= 400:
                    g._threat_detected = True
                analyzer = get_behavior_analyzer()
                norm_ep = _norm_endpoint(request.path)
                analyzer.track_request(
                    ip=client_ip,
                    endpoint=norm_ep,
                    result="malicious" if response.status_code >= 400 else "safe",
                    threat_level=_threat_from_status(response.status_code),
                )
            except Exception:
                pass

        return response


def _threat_from_status(code: int) -> str:
    if code >= 500: return "high"
    if code >= 400: return "medium"
    return "none"


def _action_tag(path: str, status: int) -> str:
    if status == 429: return "rate_limited"
    if status == 401: return "unauthorized"
    if status == 403: return "forbidden"
    if status >= 500: return "server_error"
    if path.startswith("/api/detect"): return "detect"
    if path.startswith("/api/simulate"): return "simulate"
    if path.startswith("/api/redteam"): return "redteam"
    if path.startswith("/api/campaigns"): return "campaign"
    if path.startswith("/api/tokens"): return "token_management"
    return "api_call"


def _extract_tool(path: str) -> str | None:
    parts = path.split("/")
    if len(parts) >= 3 and parts[2] in (
        "detect", "simulate", "redteam", "campaigns", "batch",
        "conversation", "compliance", "tokens", "audit",
    ):
        return parts[2]
    return None


def require_permission(tool: str):
    """视图装饰器：检查工具权限"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not getattr(config, "AUTH_ENABLED", False):
                return f(*args, **kwargs)
            from services.tool_permissions import check_permission
            meta = getattr(g, "token_meta", None)
            if not meta:
                return jsonify({"code": "FORBIDDEN", "success": False, "message": "No token."}), 403
            allowed, reason = check_permission(meta["name"], tool)
            if not allowed:
                return jsonify({
                    "code": "FORBIDDEN",
                    "success": False,
                    "message": f"Token '{meta['name']}' lacks '{tool}' permission. Reason: {reason}",
                }), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator
