"""行为风险引擎 — 会话/IP/Token 三级风险累积与处置"""
import threading
import time
from collections import defaultdict, deque


class RiskEngine:
    def __init__(self):
        self._lock = threading.RLock()
        self._ip_scores = defaultdict(int)
        self._token_scores = defaultdict(int)
        self._session_scores = defaultdict(int)
        self._history = deque(maxlen=1000)

    def record(self, ip: str = None, token: str = None, session: str = None, score: int = 0, reason: str = "", source: str = "") -> dict:
        with self._lock:
            now = time.time()
            if ip:
                self._ip_scores[ip] += score
            if token:
                self._token_scores[token] += score
            if session:
                self._session_scores[session] += score
            action = self._decide_action(ip, token, session)
            self._history.append({
                "ts": now,
                "ip": ip,
                "token": token,
                "session": session,
                "score": score,
                "reason": reason,
                "source": source,
                "action": action,
            })
            return {
                "ip_score": self._ip_scores.get(ip, 0) if ip else 0,
                "token_score": self._token_scores.get(token, 0) if token else 0,
                "session_score": self._session_scores.get(session, 0) if session else 0,
                "action": action,
            }

    def _decide_action(self, ip: str, token: str, session: str) -> str:
        max_score = max(
            self._ip_scores.get(ip, 0) if ip else 0,
            self._token_scores.get(token, 0) if token else 0,
            self._session_scores.get(session, 0) if session else 0,
        )
        if max_score >= 120:
            return "block"
        if max_score >= 70:
            return "readonly"
        if max_score >= 35:
            return "challenge"
        return "allow"

    def get_summary(self) -> dict:
        with self._lock:
            top_ips = sorted(self._ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
            top_tokens = sorted(self._token_scores.items(), key=lambda x: x[1], reverse=True)[:10]
            return {
                "top_risky_ips": [{"ip": k, "score": v} for k, v in top_ips],
                "top_risky_tokens": [{"token": k, "score": v} for k, v in top_tokens],
                "recent_actions": list(self._history)[-20:],
            }


_ENGINE = None
_ENGINE_LOCK = threading.Lock()


def get_risk_engine() -> RiskEngine:
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            _ENGINE = RiskEngine()
        return _ENGINE
