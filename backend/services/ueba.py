"""UEBA — User & Entity Behavior Analytics（Phase 4）
基于基线学习的用户/实体行为异常检测：
1. 每个 IP 的请求频率基线（前 100 请求）
2. 每个 token 的典型使用时间窗口
3. 跨 IP 使用同一 token 的关联分析
4. 异常偏离基线时提升风险分
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from collections import defaultdict, deque
import json
import time
from pathlib import Path
from threading import Lock


@dataclass
class IPBaseline:
    """IP 基线画像"""
    first_seen: float = 0
    total_requests: int = 0
    avg_rate: float = 0.0        # 请求/分钟
    endpoints: Set[str] = field(default_factory=set)
    tokens: Set[str] = field(default_factory=set)
    ips_used: Set[str] = field(default_factory=set)  # token -> 跨 IP 记录
    tool_usage: Set[str] = field(default_factory=set)
    recent_requests: deque = field(default_factory=lambda: deque(maxlen=100))
    rate_samples: deque = field(default_factory=lambda: deque(maxlen=10))  # 滑动平均


@dataclass
class TokenBaseline:
    """Token 基线画像"""
    first_seen: float = 0
    total_requests: int = 0
    avg_rate: float = 0.0
    typical_hours: Set[int] = field(default_factory=set)  # 典型使用小时
    typical_ips: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    recent_requests: deque = field(default_factory=lambda: deque(maxlen=100))


class UebaEngine:
    """
    UEBA 核心引擎。
    与 BehaviorAnalyzer 不同：BehaviorAnalyzer 基于固定阈值，
    UEBA 基于自学习基线（无需人工设定阈值）。
    """

    SNAPSHOT_FILE = Path(__file__).parent.parent / "data" / "ueba_snapshot.json"

    def __init__(self):
        self._lock = Lock()
        self._ip_baselines: Dict[str, IPBaseline] = {}
        self._token_baselines: Dict[str, TokenBaseline] = {}
        self._last_cleanup = time.time()
        self._load_snapshot()

    # ── 记录请求 ──────────────────────────────────────────────────────────

    def track_ip_request(self, ip: str, endpoint: str, token: str = None,
                        tool: str = None, result: str = "safe") -> Dict:
        """记录 IP 请求，更新基线，返回异常报告"""
        now = time.time()
        with self._lock:
            if ip not in self._ip_baselines:
                self._ip_baselines[ip] = IPBaseline(first_seen=now)

            baseline = self._ip_baselines[ip]
            baseline.total_requests += 1
            baseline.endpoints.add(self._norm_ep(endpoint))
            if tool:
                baseline.tool_usage.add(tool)
            baseline.recent_requests.append(now)

            if token:
                baseline.tokens.add(token)

            # 更新请求速率基线
            self._update_ip_rate(baseline, now)

            # 异常检测
            anomaly = self._detect_ip_anomaly(baseline, ip, endpoint, result)
            self._cleanup_if_needed(now)
            self._save_snapshot()
            return anomaly

    def track_token_request(self, token: str, ip: str, endpoint: str) -> Dict:
        """记录 Token 请求，更新基线"""
        now = time.time()
        with self._lock:
            if token not in self._token_baselines:
                self._token_baselines[token] = TokenBaseline(first_seen=now)

            baseline = self._token_baselines[token]
            baseline.total_requests += 1
            baseline.typical_hours.add(int(time.localtime(now).tm_hour))
            baseline.typical_ips.add(ip)
            baseline.endpoints.add(self._norm_ep(endpoint))
            baseline.recent_requests.append(now)

            self._update_token_rate(baseline, now)

            anomaly = self._detect_token_anomaly(baseline, token, ip, endpoint)
            self._save_snapshot()
            return anomaly

    def track_cross_ip_token(self, token: str, ip: str):
        """记录 token 跨 IP 使用（用于关联分析）"""
        with self._lock:
            if token not in self._token_baselines:
                return
            baseline = self._token_baselines[token]
            if ip not in baseline.typical_ips:
                baseline.typical_ips.add(ip)

    # ── 基线更新 ────────────────────────────────────────────────────────

    def _update_ip_rate(self, baseline: IPBaseline, now: float):
        if len(baseline.recent_requests) < 2:
            return
        dt = now - baseline.recent_requests[0]
        if dt > 0:
            rate = len(baseline.recent_requests) / (dt / 60)
            baseline.rate_samples.append(rate)
            baseline.avg_rate = sum(baseline.rate_samples) / len(baseline.rate_samples)

    def _update_token_rate(self, baseline: TokenBaseline, now: float):
        if len(baseline.recent_requests) < 2:
            return
        dt = now - baseline.recent_requests[0]
        if dt > 0:
            rate = len(baseline.recent_requests) / (dt / 60)
            baseline.avg_rate = rate

    # ── 异常检测 ───────────────────────────────────────────────────────

    def _detect_ip_anomaly(self, baseline: IPBaseline, ip: str,
                           endpoint: str, result: str) -> Dict:
        alerts = []
        score = 0

        # 1. 速率异常：当前速率超过基线 3 倍
        if baseline.avg_rate > 0 and len(baseline.rate_samples) >= 3:
            recent_dt = baseline.recent_requests[-1] - baseline.recent_requests[-5]
            recent_rate = 4 / (recent_dt / 60) if recent_dt > 0 else 0
            if recent_rate > baseline.avg_rate * 3:
                score += 30
                alerts.append({"type": "rate_spike", "detail": f"速率突增 {recent_rate:.1f}/min (基线 {baseline.avg_rate:.1f})"})

        # 2. 端点扫描：访问过多陌生端点
        known_endpoints = len(baseline.endpoints)
        if known_endpoints > 10:
            total_tried = known_endpoints + len(baseline.tool_usage)
            if total_tried > known_endpoints + 5:
                score += 25
                alerts.append({"type": "endpoint_proliferation", "detail": f"端点扫描检测，陌生端点数 {total_tried}"})

        # 3. 恶意请求聚类
        if result == "malicious" and baseline.total_requests > 5:
            malicious_ratio = 1 / baseline.total_requests
            if baseline.total_requests <= 10:
                score += 40
                alerts.append({"type": "early_malicious", "detail": "早期恶意行为，快速命中攻击模式"})

        return {"ip": ip, "anomaly_score": score, "alerts": alerts, "baseline_requests": baseline.total_requests}

    def _detect_token_anomaly(self, baseline: TokenBaseline, token: str,
                              ip: str, endpoint: str) -> Dict:
        alerts = []
        score = 0

        # 1. 跨 IP 使用（关联分析）
        if ip not in baseline.typical_ips and len(baseline.typical_ips) > 0:
            score += 35
            alerts.append({
                "type": "cross_ip_token",
                "detail": f"Token 从陌生 IP {ip} 使用（已知 IP: {len(baseline.typical_ips)} 个）"
            })

        # 2. 时间窗口异常（token 通常在工作时间使用，但现在是凌晨）
        current_hour = int(time.localtime(time.time()).tm_hour)
        if baseline.total_requests > 5 and current_hour not in baseline.typical_hours:
            if current_hour < 6 or current_hour > 22:
                score += 20
                alerts.append({"type": "unusual_hour", "detail": f"Token 在非常规时间 {current_hour}:00 使用"})

        # 3. 端点异常
        norm_ep = self._norm_ep(endpoint)
        if norm_ep not in baseline.endpoints and baseline.total_requests > 20:
            new_endpoint_ratio = 1 / (baseline.total_requests - len(baseline.endpoints) + 1)
            if new_endpoint_ratio > 0.05:
                score += 15
                alerts.append({"type": "unusual_endpoint", "detail": f"Token 访问陌生端点 {norm_ep}"})

        return {"token": token, "anomaly_score": score, "alerts": alerts, "baseline_requests": baseline.total_requests}

    # ── 查询接口 ───────────────────────────────────────────────────────

    def get_ip_report(self, ip: str) -> Dict:
        with self._lock:
            if ip not in self._ip_baselines:
                return {"found": False, "ip": ip}
            b = self._ip_baselines[ip]
            return {
                "found": True,
                "ip": ip,
                "total_requests": b.total_requests,
                "avg_rate": round(b.avg_rate, 2),
                "endpoint_count": len(b.endpoints),
                "tool_count": len(b.tool_usage),
                "token_count": len(b.tokens),
                "first_seen": b.first_seen,
            }

    def get_token_report(self, token: str) -> Dict:
        with self._lock:
            if token not in self._token_baselines:
                return {"found": False, "token": token}
            b = self._token_baselines[token]
            return {
                "found": True,
                "token": token,
                "total_requests": b.total_requests,
                "avg_rate": round(b.avg_rate, 2),
                "typical_ips": list(b.typical_ips),
                "typical_hours": sorted(b.typical_hours),
                "endpoint_count": len(b.endpoints),
                "first_seen": b.first_seen,
            }

    def get_summary(self) -> Dict:
        with self._lock:
            top_ips = sorted(
                self._ip_baselines.items(),
                key=lambda x: x[1].total_requests,
                reverse=True
            )[:20]
            return {
                "total_tracked_ips": len(self._ip_baselines),
                "total_tracked_tokens": len(self._token_baselines),
                "top_ips": [
                    {"ip": ip, "requests": b.total_requests, "avg_rate": round(b.avg_rate, 2)}
                    for ip, b in top_ips
                ],
            }

    def clear_ip(self, ip: str):
        with self._lock:
            self._ip_baselines.pop(ip, None)

    def clear_token(self, token: str):
        with self._lock:
            self._token_baselines.pop(token, None)
            self._save_snapshot()

    def _save_snapshot(self):
        try:
            payload = {
                "ips": {
                    ip: {
                        "first_seen": b.first_seen,
                        "total_requests": b.total_requests,
                        "avg_rate": b.avg_rate,
                        "endpoints": list(b.endpoints),
                        "tokens": list(b.tokens),
                        "tool_usage": list(b.tool_usage),
                    }
                    for ip, b in self._ip_baselines.items()
                },
                "tokens": {
                    token: {
                        "first_seen": b.first_seen,
                        "total_requests": b.total_requests,
                        "avg_rate": b.avg_rate,
                        "typical_hours": list(b.typical_hours),
                        "typical_ips": list(b.typical_ips),
                        "endpoints": list(b.endpoints),
                    }
                    for token, b in self._token_baselines.items()
                },
            }
            self.SNAPSHOT_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _load_snapshot(self):
        try:
            if not self.SNAPSHOT_FILE.exists():
                return
            payload = json.loads(self.SNAPSHOT_FILE.read_text(encoding="utf-8"))
            for ip, data in payload.get("ips", {}).items():
                b = IPBaseline(first_seen=data.get("first_seen", time.time()))
                b.total_requests = data.get("total_requests", 0)
                b.avg_rate = data.get("avg_rate", 0.0)
                b.endpoints = set(data.get("endpoints", []))
                b.tokens = set(data.get("tokens", []))
                b.tool_usage = set(data.get("tool_usage", []))
                self._ip_baselines[ip] = b
            for token, data in payload.get("tokens", {}).items():
                b = TokenBaseline(first_seen=data.get("first_seen", time.time()))
                b.total_requests = data.get("total_requests", 0)
                b.avg_rate = data.get("avg_rate", 0.0)
                b.typical_hours = set(data.get("typical_hours", []))
                b.typical_ips = set(data.get("typical_ips", []))
                b.endpoints = set(data.get("endpoints", []))
                self._token_baselines[token] = b
        except Exception:
            pass

    # ── 内部 ───────────────────────────────────────────────────────────

    def _norm_ep(self, path: str) -> str:
        parts = path.split("/")
        if len(parts) >= 3:
            return "/".join(parts[:3])
        return path

    def _cleanup_if_needed(self, now: float):
        if now - self._last_cleanup < 300:
            return
        self._last_cleanup = now
        # 清理 30 分钟无活动的基线
        cutoff = now - 1800
        dead_ips = [k for k, v in self._ip_baselines.items()
                    if v.recent_requests and v.recent_requests[-1] < cutoff]
        for k in dead_ips:
            del self._ip_baselines[k]
        dead_tokens = [k for k, v in self._token_baselines.items()
                       if v.recent_requests and v.recent_requests[-1] < cutoff]
        for k in dead_tokens:
            del self._token_baselines[k]


# 全局单例
_ueba_engine = None
_ueba_lock = Lock()


def get_ueba_engine() -> UebaEngine:
    global _ueba_engine
    with _ueba_lock:
        if _ueba_engine is None:
            _ueba_engine = UebaEngine()
        return _ueba_engine
