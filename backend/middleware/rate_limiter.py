"""滑动窗口请求限流 — 无需 Redis，纯内存实现"""
from flask import request, jsonify, g
from threading import Lock
from datetime import datetime, timezone
import time as _time

# ── 限流配置 ────────────────────────────────────────────────────────────────
RATE_LIMITS = {
    "/api/detect":    (60, 60),
    "/api/redteam":   (10, 60),
    "/api/export":    (5, 60),
    "/api/simulate":  (30, 60),
    "/api/batch":     (5, 60),
    "default":       (100, 60),
}

_WHITELIST = {"/", "/api/health", "/favicon.ico"}


class SlidingWindowRateLimiter:
    """滑动时间窗口限流器，按 IP 追踪"""

    def __init__(self):
        self._windows = {}
        self._lock = Lock()
        self._cleanup_ts = _time.time()
        self._cleanup_interval = 300

    def _get_limit(self, path: str):
        for prefix, limit in RATE_LIMITS.items():
            if prefix != "default" and path.startswith(prefix):
                return limit
        return RATE_LIMITS["default"]

    def _cleanup(self):
        now = _time.time()
        if now - self._cleanup_ts < self._cleanup_interval:
            return
        with self._lock:
            self._cleanup_ts = now
            expired_ips = []
            for ip, paths in self._windows.items():
                expired_paths = {}
                for p, entries in paths.items():
                    window_seconds = self._get_limit(p)[1]
                    cutoff = now - window_seconds
                    entries[:] = [e for e in entries if e[0] > cutoff]
                    if not entries:
                        expired_paths[p] = True
                for p in expired_paths:
                    del paths[p]
                if not paths:
                    expired_ips.append(ip)
            for ip in expired_ips:
                del self._windows[ip]

    def is_allowed(self, ip: str, path: str):
        """返回 (是否允许, 限流信息字典)"""
        if path in _WHITELIST:
            return True, {}

        self._cleanup()
        max_requests, window_seconds = self._get_limit(path)
        now = _time.time()
        key = f"{ip}:{path}"

        with self._lock:
            if key not in self._windows:
                self._windows[key] = {}

            entries = self._windows[key].setdefault(path, [])
            cutoff = now - window_seconds
            entries[:] = [e for e in entries if e[0] > cutoff]

            current_count = len(entries)
            remaining = max(0, max_requests - current_count)
            reset_ts = int(now + window_seconds)

            if current_count >= max_requests:
                oldest = entries[0][0] if entries else now
                retry_after = int(oldest + window_seconds - now)
                return False, {
                    "limit": max_requests,
                    "remaining": 0,
                    "reset": reset_ts,
                    "retry_after": max(1, retry_after),
                }

            entries.append((now, 1))
            return True, {
                "limit": max_requests,
                "remaining": remaining - 1,
                "reset": reset_ts,
            }


_rate_limiter = SlidingWindowRateLimiter()


def setup_rate_limiter(app):
    """
    在 create_app() 中调用，注册 before_request 和 after_request。
    after_request 必须在请求处理前注册，不能在 before_request 里注册。
    """

    @app.before_request
    def _limit():
        path = request.path
        if path in _WHITELIST or not path.startswith("/api/"):
            return None

        ip = request.remote_addr or "127.0.0.1"
        allowed, info = _rate_limiter.is_allowed(ip, path)

        if not allowed:
            response = jsonify({
                "success": False,
                "code": "RATE_LIMITED",
                "message": f"请求过于频繁，请 {info.get('retry_after', 60)} 秒后重试",
                "request_id": getattr(g, "request_id", ""),
            })
            response.headers["X-RateLimit-Limit"]     = str(info.get("limit", 0))
            response.headers["X-RateLimit-Remaining"] = "0"
            response.headers["X-RateLimit-Reset"]    = str(info.get("reset", 0))
            response.headers["Retry-After"]        = str(info.get("retry_after", 60))
            return response, 429

        # 存入 g 供 after_request 使用（per-request 上下文安全）
        g._rate_info = info
        return None

    @app.after_request
    def _add_rate_headers(response):
        info = getattr(g, "_rate_info", None)
        if info:
            response.headers["X-RateLimit-Limit"]     = str(info.get("limit", 0))
            response.headers["X-RateLimit-Remaining"] = str(info.get("remaining", 0))
            response.headers["X-RateLimit-Reset"]    = str(info.get("reset", 0))
        return response
