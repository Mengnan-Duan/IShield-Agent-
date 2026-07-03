"""Per-token independent rate limiting -- each token has its own sliding window counter"""
import time
import threading
from typing import Dict, Tuple

# Per-token: no endpoint breakdown, one global counter per token
TOKEN_RATE_LIMITS = {
    "admin": 500,
    "operator": 300,
    "analyst": 200,
    "readonly": 100,
    # Dev/demo UI fan-outs several read APIs after each action. Keep these
    # high enough to avoid blocking local interactive workflows.
    "guest": 600,
    "anonymous": 600,
}
WINDOW_SIZE = 60.0


class TokenRateLimiter:
    def __init__(self):
        self._lock = threading.RLock()
        # key = token_name, value = list of request timestamps
        self._windows: Dict[str, list] = {}

    def check(self, token_name: str, role: str = "guest") -> Tuple[bool, int, int]:
        limit = TOKEN_RATE_LIMITS.get(role, TOKEN_RATE_LIMITS["guest"])
        ts = time.time()

        with self._lock:
            if token_name not in self._windows:
                self._windows[token_name] = []

            window = self._windows[token_name]
            # Sliding window cleanup
            window[:] = [t for t in window if ts - t < WINDOW_SIZE]
            count = len(window)

            if count >= limit:
                return False, count, limit

            window.append(ts)
            return True, count + 1, limit

    def get_stats(self) -> dict:
        ts = time.time()
        with self._lock:
            details = []
            for token, window in list(self._windows.items()):
                window[:] = [x for x in window if ts - x < WINDOW_SIZE]
                cnt = len(window)
                if cnt > 0:
                    details.append({"token": token, "requests_in_window": cnt})
            return {"active_tokens": len(details), "details": details[:100]}


_token_rate_limiter = TokenRateLimiter()


def get_token_rate_limiter() -> TokenRateLimiter:
    return _token_rate_limiter
