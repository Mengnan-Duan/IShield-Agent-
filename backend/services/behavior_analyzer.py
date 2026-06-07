"""行为异常检测引擎 — 基于滑动窗口统计 IP 行为模式"""
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional
from middleware.logger import get_logger

logger = get_logger()

# 配置常量
WINDOW_SIZE_SECONDS = 300       # 5分钟滑动窗口
ANOMALY_THRESHOLD = 30          # 30次请求/窗口 = 异常
SCAN_THRESHOLD = 8              # 跨端点数超过此值 = 端口扫描行为
RAPID_FIRE_THRESHOLD = 10       # 10次恶意请求/分钟 = 定向攻击
BANNED_THRESHOLD = 50           # 超过此值自动封禁 IP（段时间内）

RECENT_MALICIOUS = 60          # 最近60秒内的恶意请求才计入 rapid-fire


@dataclass
class IPProfile:
    """单个 IP 的行为档案"""
    ip: str
    requests: List[tuple] = field(default_factory=list)   # [(timestamp, endpoint, result)]
    malicious_count: int = 0
    endpoints_hit: set = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    score: int = 0                 # 累计异常分
    is_banned: bool = False
    ban_until: float = 0.0


class BehaviorAnalyzer:
    """
    滑动窗口行为异常检测。

    检测模式：
    1. 请求频率异常（短时间内大量请求）
    2. 端点扫描（短时间内访问大量不同端点）
    3. 恶意请求聚集（短时间内多次触发拦截）
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._profiles: dict[str, IPProfile] = {}
        self._global_malicious: dict[str, List[float]] = defaultdict(list)  # ip -> [timestamps of malicious reqs]
        self._cleanup_ts = 0.0
        self._cleanup_interval = 60.0

    # ── 公共 API ──────────────────────────────────────────────────────────────

    def track_request(self, ip: str, endpoint: str, result: str, threat_level: str = "low") -> None:
        """记录一次请求，返回是否需要限流"""
        self._maybe_cleanup()
        ts = time.time()

        with self._lock:
            profile = self._profiles.setdefault(ip, IPProfile(ip=ip))
            profile.requests.append((ts, endpoint, result))
            profile.last_seen = ts
            profile.endpoints_hit.add(endpoint)

            if result in ("blocked", "malicious"):
                profile.malicious_count += 1
                self._global_malicious[ip].append(ts)

            # 更新异常分
            self._recompute_score(profile)

            # 自动封禁
            if profile.score >= BANNED_THRESHOLD and not profile.is_banned:
                profile.is_banned = True
                profile.ban_until = ts + 300  # 封禁5分钟
                logger.warning(f"[BehaviorGuard] IP {ip} auto-banned for 5 min (score={profile.score})")

    def is_banned(self, ip: str) -> bool:
        ts = time.time()
        with self._lock:
            p = self._profiles.get(ip)
            if p and p.is_banned:
                if ts > p.ban_until:
                    p.is_banned = False
                    p.score = max(0, p.score - 20)
                    return False
                return True
        return False

    def get_anomaly_score(self, ip: str) -> int:
        with self._lock:
            p = self._profiles.get(ip)
            return p.score if p else 0

    def get_summary(self) -> dict:
        """返回全局异常摘要"""
        self._maybe_cleanup()
        with self._lock:
            now = time.time()
            anomalies = []
            for ip, p in self._profiles.items():
                if p.score >= ANOMALY_THRESHOLD / 2:  # 中等以上风险
                    recency = now - p.last_seen
                    anomalies.append({
                        "ip": ip,
                        "score": p.score,
                        "total_requests": len(p.requests),
                        "malicious_count": p.malicious_count,
                        "endpoints_hit": len(p.endpoints_hit),
                        "last_seen": p.last_seen,
                        "recency_seconds": int(recency),
                        "is_banned": p.is_banned,
                        "threat_level": _score_to_level(p.score),
                    })
            anomalies.sort(key=lambda x: x["score"], reverse=True)
            return {
                "total_tracked_ips": len(self._profiles),
                "anomaly_count": len(anomalies),
                "top_anomalies": anomalies[:20],
            }

    def get_ip_report(self, ip: str) -> dict:
        """返回指定 IP 的详细行为报告"""
        self._maybe_cleanup()
        now = time.time()
        with self._lock:
            p = self._profiles.get(ip)
            if not p:
                return {"ip": ip, "found": False}

            recent_requests = [
                {"ts": ts, "endpoint": ep, "result": res}
                for ts, ep, res in p.requests if now - ts < WINDOW_SIZE_SECONDS
            ]
            recent_malicious = [ts for ts in self._global_malicious.get(ip, []) if now - ts < RECENT_MALICIOUS]

            return {
                "ip": ip,
                "found": True,
                "score": p.score,
                "threat_level": _score_to_level(p.score),
                "is_banned": p.is_banned,
                "total_requests": len(p.requests),
                "malicious_count": p.malicious_count,
                "endpoints_hit": sorted(p.endpoints_hit),
                "first_seen": p.first_seen,
                "last_seen": p.last_seen,
                "requests_in_window": len(recent_requests),
                "recent_requests": recent_requests[-20:],
                "rapid_fire_malicious": len(recent_malicious),
                "request_rate": len(recent_requests) / (WINDOW_SIZE_SECONDS / 60),
            }

    def get_threat_level(self, ip: str) -> str:
        return _score_to_level(self.get_anomaly_score(ip))

    # ── 内部 ────────────────────────────────────────────────────────────────

    def _recompute_score(self, profile: IPProfile) -> None:
        now = time.time()
        # 清理窗口外请求
        profile.requests = [(ts, ep, res) for ts, ep, res in profile.requests
                            if now - ts < WINDOW_SIZE_SECONDS]
        profile.endpoints_hit = set(ep for ts, ep, _ in profile.requests)

        req_count = len(profile.requests)
        endpoint_count = len(profile.endpoints_hit)
        malicious_ratio = profile.malicious_count / max(req_count, 1)

        score = 0
        # 请求频率
        if req_count > ANOMALY_THRESHOLD:
            score += min((req_count - ANOMALY_THRESHOLD) * 2, 30)
        # 端口扫描
        if endpoint_count > SCAN_THRESHOLD:
            score += min((endpoint_count - SCAN_THRESHOLD) * 3, 20)
        # 恶意请求比例
        if malicious_ratio > 0.5:
            score += int(malicious_ratio * 30)
        # 聚集攻击
        recent_mal = [ts for ts in self._global_malicious.get(profile.ip, []) if now - ts < RECENT_MALICIOUS]
        if len(recent_mal) >= RAPID_FIRE_THRESHOLD:
            score += 20

        profile.score = min(score, 100)

    def _maybe_cleanup(self) -> None:
        now = time.time()
        if now - self._cleanup_ts < self._cleanup_interval:
            return
        self._cleanup_ts = now
        with self._lock:
            stale = [ip for ip, p in self._profiles.items() if now - p.last_seen > 1800]
            for ip in stale:
                del self._profiles[ip]
            for ip in list(self._global_malicious):
                self._global_malicious[ip] = [ts for ts in self._global_malicious[ip] if now - ts < RECENT_MALICIOUS * 2]


_behavior_analyzer = BehaviorAnalyzer()


def get_behavior_analyzer() -> BehaviorAnalyzer:
    return _behavior_analyzer


def _score_to_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    if score >= 10:
        return "low"
    return "none"
