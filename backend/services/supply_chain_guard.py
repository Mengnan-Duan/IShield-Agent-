"""供应链安全审计服务 — Phase 4
监控所有出站 HTTP 请求，检测数据外泄模式和供应链风险。
对应《实施意见》第 9 条：供应链安全管理。
"""
import re
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ── 高风险域名模式 ──────────────────────────────────────────────────────────
HIGH_RISK_DOMAINS = {
    "pastebin", "throwbin", "hastebin", " requestbin",
    "ipinfo.io", "ip-api.com",  # 信息收集
}

# ── 数据外泄模式 ───────────────────────────────────────────────────────────
EXFILTRATION_PATTERNS = [
    # 大量字段提取
    (r"(select|extract|retrieve).{0,50}(email|user|passwd|phone|address|credit)", 30),
    # 配置信息外发
    (r"(api_key|secret|token|credential|auth).{0,30}(send|post|http|upload)", 50),
    # 数据库导出
    (r"(export|dump|backup).{0,30}(db|database|table|schema)", 40),
    # 凭证外泄
    (r"(password|hash|private).{0,20}(write|send|post|upload)", 50),
]

# ── 用户代理指纹 ────────────────────────────────────────────────────────────
KNOWN_BENIGN_UA_PREFIXES = {
    "python-requests", "curl", "axios", "fetch", "okhttp",
    "Apache-HttpClient", "Java/", "Go-http-client",
}

SUSPICIOUS_UA_PATTERNS = {
    "curl", "wget", "python", "java", "go",
}


@dataclass
class HTTPRequestRecord:
    """单次 HTTP 请求记录"""
    timestamp: float
    domain: str
    method: str
    path: str
    status_code: int
    response_bytes: int
    chain_id: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class DomainProfile:
    """域名画像"""
    first_seen: float = 0
    request_count: int = 0
    total_response_bytes: int = 0
    methods: Set[str] = field(default_factory=set)
    paths: Set[str] = field(default_factory=set)
    chain_ids: Set[str] = field(default_factory=set)
    suspicious: bool = False
    risk_score: int = 0


class SupplyChainGuard:
    """
    供应链安全守卫。
    记录所有出站 HTTP 请求，分析数据外泄模式。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._domain_profiles: Dict[str, DomainProfile] = {}
        self._request_history: deque = deque(maxlen=1000)  # 最近 1000 条记录
        self._last_cleanup = time.time()

    def record_request(self, domain: str, method: str, path: str,
                      status_code: int, response_bytes: int,
                      chain_id: str = None, request_id: str = None) -> Dict:
        """
        记录一次 HTTP 请求，返回分析结果。
        """
        now = time.time()
        with self._lock:
            if domain not in self._domain_profiles:
                self._domain_profiles[domain] = DomainProfile(first_seen=now)

            profile = self._domain_profiles[domain]
            profile.request_count += 1
            profile.total_response_bytes += response_bytes
            profile.methods.add(method.upper())
            profile.paths.add(path)
            if chain_id:
                profile.chain_ids.add(chain_id)

            record = HTTPRequestRecord(
                timestamp=now,
                domain=domain,
                method=method.upper(),
                path=path,
                status_code=status_code,
                response_bytes=response_bytes,
                chain_id=chain_id,
                request_id=request_id,
            )
            self._request_history.append(record)

            # 风险评估
            alerts = self._assess_domain_risk(profile, domain, path, method)
            profile.risk_score = sum(a["score"] for a in alerts)
            profile.suspicious = profile.risk_score >= 30

            self._cleanup_if_needed(now)
            return {"domain": domain, "risk_score": profile.risk_score, "alerts": alerts, "profile": self._profile_summary(profile)}

    def _assess_domain_risk(self, profile: DomainProfile, domain: str,
                           path: str, method: str) -> List[Dict]:
        alerts = []
        lower_domain = domain.lower()
        lower_path = (path or "").lower()

        # 1. 高风险域名
        for risky in HIGH_RISK_DOMAINS:
            if risky in lower_domain:
                alerts.append({"type": "high_risk_domain", "domain": domain, "score": 50})
                break

        # 2. 外部服务暴露数据
        combined = lower_domain + " " + lower_path
        for pattern, score in EXFILTRATION_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                alerts.append({"type": "data_exfiltration_pattern", "pattern": pattern, "score": score})
                break

        # 3. 大量数据外发（>1MB 单次响应）
        if profile.total_response_bytes > 1024 * 1024 and profile.request_count == 1:
            alerts.append({"type": "large_response", "bytes": profile.total_response_bytes, "score": 25})

        # 4. 同一 chain_id 大量请求到陌生域名
        if len(profile.chain_ids) == 1 and profile.request_count > 5:
            alerts.append({"type": "repeated_chain_requests", "count": profile.request_count, "score": 20})

        # 5. 未知域名首次访问
        if profile.request_count == 1 and lower_domain not in self._get_known_safe_domains():
            alerts.append({"type": "unknown_domain", "domain": domain, "score": 15})

        return alerts

    def _get_known_safe_domains(self) -> Set[str]:
        """已知安全域名（来自配置白名单）"""
        try:
            import config
            return set(getattr(config, "SANDBOX_ALLOWED_DOMAINS", set()))
        except Exception:
            return set()

    def _profile_summary(self, profile: DomainProfile) -> Dict:
        return {
            "request_count": profile.request_count,
            "total_bytes": profile.total_response_bytes,
            "methods": list(profile.methods),
            "first_seen": profile.first_seen,
            "suspicious": profile.suspicious,
            "risk_score": profile.risk_score,
        }

    def get_domain_report(self, domain: str) -> Dict:
        with self._lock:
            if domain not in self._domain_profiles:
                return {"found": False, "domain": domain}
            profile = self._domain_profiles[domain]
            return {
                "found": True,
                "domain": domain,
                **self._profile_summary(profile),
                "paths": list(profile.paths)[:20],
                "chain_ids": list(profile.chain_ids)[:10],
            }

    def get_all_suspicious(self) -> List[Dict]:
        with self._lock:
            return [
                {"domain": d, **self._profile_summary(p)}
                for d, p in self._domain_profiles.items()
                if p.suspicious
            ]

    def get_summary(self) -> Dict:
        with self._lock:
            total_requests = sum(p.request_count for p in self._domain_profiles.values())
            suspicious_count = sum(1 for p in self._domain_profiles.values() if p.suspicious)
            top_domains = sorted(
                self._domain_profiles.items(),
                key=lambda x: x[1].request_count,
                reverse=True
            )[:10]
            return {
                "total_domains_accessed": len(self._domain_profiles),
                "total_requests": total_requests,
                "suspicious_domains": suspicious_count,
                "top_domains": [
                    {"domain": d, "requests": p.request_count, "bytes": p.total_response_bytes,
                     "suspicious": p.suspicious, "risk_score": p.risk_score}
                    for d, p in top_domains
                ],
            }

    def _cleanup_if_needed(self, now: float):
        if now - self._last_cleanup < 600:
            return
        self._last_cleanup = now
        cutoff = now - 3600
        dead = [d for d, p in self._domain_profiles.items()
                if p.first_seen < cutoff and p.request_count <= 2]
        for d in dead:
            del self._domain_profiles[d]


# 全局单例
_supply_chain_guard = None
_scfg_lock = threading.Lock()


def get_supply_chain_guard() -> SupplyChainGuard:
    global _supply_chain_guard
    with _scfg_lock:
        if _supply_chain_guard is None:
            _supply_chain_guard = SupplyChainGuard()
        return _supply_chain_guard
