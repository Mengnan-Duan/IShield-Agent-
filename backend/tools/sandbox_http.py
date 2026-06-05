"""HTTP请求沙箱 — 域名白名单 + SSRF 防护 + 响应限制"""
import requests, sys, os, socket, ipaddress
from urllib.parse import urlparse, urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

DEFAULT_ALLOWED_DOMAINS = {
    "api.github.com",
    "httpbin.org",
    "jsonplaceholder.typicode.com",
    "api.openweathermap.org",
    "api.exchangerate-api.com",
}
BLOCKED_PORTS = {21, 23, 25, 110, 143, 3306, 5432, 6379, 27017}


class HTTPSandbox:
    """安全的HTTP请求代理"""

    def __init__(self, allowed_domains: set = None):
        self.allowed_domains = allowed_domains or set(
            getattr(config, "SANDBOX_ALLOWED_DOMAINS", None) or DEFAULT_ALLOWED_DOMAINS
        )
        self.allowed_suffixes = set(getattr(config, "SANDBOX_ALLOWED_DOMAIN_SUFFIXES", set()) or set())
        self.allowed_content_types = set(getattr(config, "SANDBOX_HTTP_ALLOWED_CONTENT_TYPES", {"application/json"}) or {"application/json"})
        self.max_response_bytes = int(getattr(config, "SANDBOX_HTTP_MAX_RESPONSE_BYTES", 20000) or 20000)
        self.max_redirects = int(getattr(config, "SANDBOX_HTTP_MAX_REDIRECTS", 3) or 3)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "IShield-Sandbox/2.0 (Security Research)",
            "Accept": "application/json, text/plain, text/html, */*",
        })
        self.session.headers.pop("Cookie", None)
        self.session.headers.pop("Authorization", None)

    def _check_url(self, url: str) -> tuple:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return None, "仅支持 http/https 协议"
            if not parsed.netloc:
                return None, "URL缺少域名"
            host = (parsed.hostname or "").lower()
            port = parsed.port
            if port and port in BLOCKED_PORTS:
                return None, f"端口 {port} 被禁止"
            if not self._host_allowed(host):
                return None, f"域名 {host} 不在白名单内"
            ip_error = self._check_host_ip(host)
            if ip_error:
                return None, ip_error
            return parsed, None
        except Exception as e:
            return None, f"URL解析失败: {e}"

    def _host_allowed(self, host: str) -> bool:
        lowered_domains = {d.lower() for d in self.allowed_domains}
        lowered_suffixes = {d.lower() for d in self.allowed_suffixes}
        if host in lowered_domains:
            return True
        return any(host.endswith(suffix) for suffix in lowered_suffixes)

    def _check_host_ip(self, host: str) -> str:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = info[4][0]
                parsed = ipaddress.ip_address(ip)
                if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast:
                    return f"目标地址 {ip} 属于内网/保留地址，已阻断"
            return ""
        except socket.gaierror:
            return "域名解析失败"
        except ValueError:
            return "目标地址非法"

    def request(self, method: str, url: str, source_ip: str = None, **kwargs) -> dict:
        method = method.upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
            return self._result("error", url, f"不支持的HTTP方法: {method}", reason="invalid_method")

        parsed, err = self._check_url(url)
        if err:
            return self._result("blocked", url, err, reason="url_blocked", severity=90, data={"source_ip": source_ip})

        safe_headers = dict(self.session.headers)
        if "headers" in kwargs:
            user_headers = kwargs.pop("headers", {}) or {}
            safe_headers.update(user_headers)
        safe_headers.pop("Cookie", None)
        safe_headers.pop("Authorization", None)
        safe_headers.pop("Proxy-Authorization", None)

        timeout = kwargs.pop("timeout", 10)
        try:
            response = self.session.request(
                method,
                url,
                timeout=timeout,
                headers=safe_headers,
                allow_redirects=False,
                **kwargs,
            )
            redirect_chain = []
            current_response = response
            current_url = url
            for _ in range(self.max_redirects):
                if current_response.is_redirect or current_response.is_permanent_redirect:
                    location = current_response.headers.get("Location")
                    if not location:
                        break
                    next_url = urljoin(current_url, location)
                    redirect_chain.append(next_url)
                    _, redirect_err = self._check_url(next_url)
                    if redirect_err:
                        return self._result("blocked", next_url, f"重定向目标被阻断: {redirect_err}", reason="redirect_blocked", severity=88)
                    current_url = next_url
                    current_response = self.session.request(method, next_url, timeout=timeout, headers=safe_headers, allow_redirects=False, **kwargs)
                else:
                    break

            content_type = (current_response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type and content_type not in {ct.lower() for ct in self.allowed_content_types}:
                return self._result("blocked", current_url, f"响应类型 {content_type} 不在允许列表", reason="content_type_blocked", severity=80)

            body = current_response.text[:self.max_response_bytes]
            truncated = len(current_response.text.encode("utf-8", errors="ignore")) > self.max_response_bytes
            return self._result(
                "executed",
                current_url,
                "HTTP 请求代理成功",
                severity=20,
                data={
                    "url": current_url,
                    "status_code": current_response.status_code,
                    "headers": dict(current_response.headers),
                    "body": body,
                    "elapsed_ms": round(current_response.elapsed.total_seconds() * 1000, 1),
                    "redirect_chain": redirect_chain,
                    "truncated": truncated,
                    "method": method,
                    "source_ip": source_ip,
                },
            )
        except requests.exceptions.Timeout:
            return self._result("error", url, "请求超时(10秒)", reason="timeout", severity=60)
        except requests.exceptions.ConnectionError:
            return self._result("error", url, "连接失败", reason="connection_error", severity=60)
        except Exception as e:
            return self._result("error", url, str(e), reason="request_error", severity=60)

    def _result(self, status: str, url: str, summary: str, reason: str = None, severity: int = 50, data: dict = None):
        parsed = urlparse(url) if url else None
        return {
            "status": status,
            "tool": "http_request",
            "mode": "real",
            "summary": summary,
            "audit": {
                "target": url,
                "host": parsed.hostname if parsed else None,
                "method": data.get("method") if data else None,
                "reason": reason,
                "severity": severity,
                "threat_level": "high" if status == "blocked" else "low",
                "allowed": status != "blocked",
            },
            "data": data or {"url": url},
        }


_sandbox = None


def get_sandbox() -> HTTPSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = HTTPSandbox()
    return _sandbox
