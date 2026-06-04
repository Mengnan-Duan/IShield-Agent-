"""HTTP请求沙箱 — 域名白名单 + 方法限制"""
import requests, sys, os
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# 域名白名单（可通过 config.py 覆盖）
DEFAULT_ALLOWED_DOMAINS = {
    "api.github.com",
    "httpbin.org",
    "jsonplaceholder.typicode.com",
    "api.openweathermap.org",
    "api.exchangerate-api.com",
}

BLOCKED_PORTS = {23, 21, 25, 110, 143, 3306, 5432, 6379, 27017}


class HTTPSandbox:
    """安全的HTTP请求代理"""

    def __init__(self, allowed_domains: set = None):
        self.allowed_domains = allowed_domains or set(
            getattr(config, "SANDBOX_ALLOWED_DOMAINS", None) or DEFAULT_ALLOWED_DOMAINS
        )
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "IShield-Sandbox/1.0 (Security Research)",
            "Accept": "application/json, text/plain, */*",
        })
        self.session.headers.pop("Cookie", None)
        self.session.headers.pop("Authorization", None)

    def _check_url(self, url: str) -> tuple:
        """检查URL安全性，返回 (parsed_url, error)"""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return None, "仅支持 http/https 协议"
            if not parsed.netloc:
                return None, "URL缺少域名"
            # 检查端口
            host = parsed.hostname or ""
            port = parsed.port
            if port and port in BLOCKED_PORTS:
                return None, f"端口 {port} 被禁止"
            # 域名白名单
            if parsed.hostname.lower() not in {d.lower() for d in self.allowed_domains}:
                return None, f"域名 {parsed.hostname} 不在白名单内: {', '.join(sorted(self.allowed_domains))}"
            return parsed, None
        except Exception as e:
            return None, f"URL解析失败: {e}"

    def request(self, method: str, url: str, **kwargs) -> dict:
        """
        执行安全的HTTP请求。

        参数:
            method: HTTP方法 (GET/POST/PUT/DELETE/HEAD/OPTIONS)
            url:    目标URL
            **kwargs: 其他requests参数（headers/body/json/params等）

        返回:
            {"status": "ok"|"error"|"blocked", "data": dict, "status_code": int}
        """
        method = method.upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
            return {"status": "error", "message": f"不支持的HTTP方法: {method}"}

        parsed, err = self._check_url(url)
        if err:
            return {"status": "blocked", "url": url, "reason": err}

        # 清理危险headers
        safe_headers = dict(self.session.headers)
        if "headers" in kwargs:
            user_headers = kwargs.pop("headers", {})
            safe_headers.update(user_headers)
            safe_headers.pop("Cookie", None)
            safe_headers.pop("Authorization", None)

        try:
            resp = self.session.request(
                method,
                url,
                timeout=kwargs.pop("timeout", 10),
                **kwargs,
                headers=safe_headers,
                allow_redirects=True,
            )
            return {
                "status": "ok",
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:5000],
                "elapsed_ms": round(resp.elapsed.total_seconds() * 1000, 1),
                "url": url,
            }
        except requests.exceptions.Timeout:
            return {"status": "error", "url": url, "reason": "请求超时(10秒)"}
        except requests.exceptions.ConnectionError:
            return {"status": "error", "url": url, "reason": "连接失败"}
        except Exception as e:
            return {"status": "error", "url": url, "reason": str(e)}

    def get(self, url: str, **kwargs) -> dict:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> dict:
        return self.request("POST", url, **kwargs)


# ── 全局单例 ────────────────────────────────────────────────────────────────
_sandbox = None

def get_sandbox() -> HTTPSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = HTTPSandbox()
    return _sandbox
