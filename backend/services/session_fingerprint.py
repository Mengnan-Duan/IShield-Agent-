"""Session fingerprinting -- cross-IP user tracking based on request characteristics"""
import hashlib
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Set, Optional

WINDOW_SIZE = 3600.0
ANOMALY_THRESHOLD = 5


@dataclass
class SessionProfile:
    fingerprint: str
    requests: list = field(default_factory=list)
    ip_set: Set[str] = field(default_factory=set)
    endpoints_set: Set[str] = field(default_factory=set)
    tools_set: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    cross_ip_count: int = 0
    score: int = 0


class SessionFingerprinter:
    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: Dict[str, SessionProfile] = {}

    def fingerprint_request(self, request) -> str:
        ua = (request.headers.get("User-Agent", "") or "")[:100]
        lang = (request.headers.get("Accept-Language", "") or "")[:50]
        auth = (request.headers.get("Authorization", "") or "")[:50]
        fingerprint = hashlib.sha1("|".join([ua, lang, auth]).encode()).hexdigest()[:16]
        return fingerprint

    def get_or_create_session(self, fingerprint: str) -> SessionProfile:
        with self._lock:
            if fingerprint not in self._sessions:
                self._sessions[fingerprint] = SessionProfile(fingerprint=fingerprint)
            return self._sessions[fingerprint]

    def track_request(
        self,
        fingerprint: str,
        ip: str,
        endpoint: str,
        result: str = "safe",
        tool: Optional[str] = None,
    ) -> SessionProfile:
        ts = time.time()
        profile = self.get_or_create_session(fingerprint)

        with self._lock:
            profile.requests.append((ts, ip, endpoint, result))
            profile.last_seen = ts
            profile.endpoints_set.add(endpoint)
            if ip not in profile.ip_set:
                profile.ip_set.add(ip)
                profile.cross_ip_count = len(profile.ip_set)
            if tool:
                profile.tools_set.add(tool)
            self._recompute_score(profile)

        return profile

    def analyze_session_anomaly(self, fingerprint: str) -> dict:
        with self._lock:
            profile = self._sessions.get(fingerprint)
            if not profile:
                return {"fingerprint": fingerprint, "found": False}

            anomalies = []
            if profile.cross_ip_count > ANOMALY_THRESHOLD:
                anomalies.append({
                    "type": "cross_ip_jump",
                    "severity": "high",
                    "message": f"Same session from {profile.cross_ip_count} different IPs",
                    "ips": sorted(profile.ip_set),
                })
            if len(profile.endpoints_set) > 15:
                anomalies.append({
                    "type": "endpoint_proliferation",
                    "severity": "medium",
                    "message": f"Session accessed {len(profile.endpoints_set)} different endpoints",
                })
            dangerous = {"email", "file", "db"}.intersection(profile.tools_set)
            if len(dangerous) >= 2:
                anomalies.append({
                    "type": "dangerous_tool_combo",
                    "severity": "high",
                    "message": f"Multiple dangerous tools used: {', '.join(dangerous)}",
                })

            return {
                "fingerprint": fingerprint,
                "found": True,
                "score": profile.score,
                "threat_level": _score_to_level(profile.score),
                "anomalies": anomalies,
                "ip_count": profile.cross_ip_count,
                "endpoint_count": len(profile.endpoints_set),
                "tool_count": len(profile.tools_set),
                "request_count": len(profile.requests),
            }

    def get_suspicious_sessions(self) -> list:
        with self._lock:
            results = []
            for fp, profile in self._sessions.items():
                if profile.score >= 10 or profile.cross_ip_count > ANOMALY_THRESHOLD:
                    results.append({
                        "fingerprint": fp,
                        "score": profile.score,
                        "threat_level": _score_to_level(profile.score),
                        "ip_count": profile.cross_ip_count,
                        "endpoint_count": len(profile.endpoints_set),
                        "last_seen": profile.last_seen,
                        "requests": len(profile.requests),
                    })
            results.sort(key=lambda x: x["score"], reverse=True)
            return results[:20]

    def _recompute_score(self, profile: SessionProfile) -> None:
        score = 0
        if profile.cross_ip_count > ANOMALY_THRESHOLD:
            score += min((profile.cross_ip_count - ANOMALY_THRESHOLD) * 5, 25)
        if len(profile.endpoints_set) > 15:
            score += min((len(profile.endpoints_set) - 15) * 2, 15)
        if {"email", "file", "db"}.intersection(profile.tools_set):
            score += 10
        now = time.time()
        recent = [(ts, ip, ep, res) for ts, ip, ep, res in profile.requests if now - ts < WINDOW_SIZE]
        mal = sum(1 for _, _, _, r in recent if r in ("blocked", "malicious"))
        if mal > 3:
            score += min(mal * 3, 30)
        profile.score = min(score, 100)


_session_fingerprinter = SessionFingerprinter()


def get_session_fingerprinter() -> SessionFingerprinter:
    return _session_fingerprinter


def _score_to_level(score: int) -> str:
    if score >= 60: return "critical"
    if score >= 35: return "high"
    if score >= 15: return "medium"
    if score >= 5:  return "low"
    return "none"
