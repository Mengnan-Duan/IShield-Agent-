"""内存 LRU 缓存 — 无需 Redis，支持 TTL"""
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from threading import Lock
import hashlib
import json
import time as _time

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class LRUCache:
    """线程安全的 LRU 缓存，支持 TTL"""

    def __init__(self, maxsize=512, ttl_seconds=600):
        self._maxsize = maxsize
        self._ttl = ttl_seconds
        self._cache = OrderedDict()  # key -> (value, expiry_timestamp)
        self._lock = Lock()
        self._hits = 0
        self._misses = 0

    def _make_key(self, *args, **kwargs) -> str:
        raw = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def get(self, key: str):
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            value, expiry = self._cache[key]
            if expiry and datetime.now(timezone.utc) > expiry:
                del self._cache[key]
                self._misses += 1
                return None
            self._cache.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: str, value, ttl: int = None):
        with self._lock:
            ttl = ttl if ttl is not None else self._ttl
            expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl) if ttl > 0 else None
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (value, expiry)
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)

    def delete(self, key: str):
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def cleanup_expired(self):
        """清理过期条目"""
        now = datetime.now(timezone.utc)
        with self._lock:
            expired = [k for k, (_, exp) in self._cache.items() if exp and now > exp]
            for k in expired:
                del self._cache[k]

    @property
    def stats(self):
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0
            return {"hits": self._hits, "misses": self._misses,
                    "size": len(self._cache), "hit_rate": round(hit_rate, 3)}


# ── 全局缓存实例 ──────────────────────────────────────────────────────────────

# 检测结果缓存：SHA256(text) -> hybrid_detect result, TTL=10min
detect_cache = LRUCache(maxsize=1024, ttl_seconds=600)

# 事件列表缓存：固定 key，返回 get_events_from_db() 结果，TTL=30s
_events_cache = {"key": None, "value": None, "expiry": None}
_events_lock = Lock()


def get_cached_events(ttl=30):
    """获取缓存的事件列表（TTL 30秒，减少 DB 查询）"""
    global _events_cache
    now = datetime.now(timezone.utc)
    with _events_lock:
        if (_events_cache["key"] is not None
                and _events_cache["expiry"] is not None
                and now < _events_cache["expiry"]):
            return _events_cache["value"]
    return None


def set_cached_events(value, ttl=30):
    """设置事件列表缓存"""
    global _events_cache
    with _events_lock:
        _events_cache = {
            "key": "events_list",
            "value": value,
            "expiry": datetime.now(timezone.utc) + timedelta(seconds=ttl)
        }


def invalidate_events_cache():
    """失效事件列表缓存（写入事件后调用）"""
    global _events_cache
    with _events_lock:
        _events_cache = {"key": None, "value": None, "expiry": None}
