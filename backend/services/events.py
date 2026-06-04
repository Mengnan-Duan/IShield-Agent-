"""事件存储服务 — SQLite + 内存缓存双写，检测缓存，DB 索引"""
import sqlite3
import os
import json
import hashlib
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import List, Optional
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from utils.cache import detect_cache, invalidate_events_cache, get_cached_events, set_cached_events

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ishield.db")
_db_lock = Lock()

_UTC8 = timezone(timedelta(hours=8))

def _local_now():
    return datetime.now(_UTC8)

# ── 初始化 ──────────────────────────────────────────────────────────────────
def init_db():
    """初始化数据库，创建表和索引（幂等操作）"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # 事件表
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time TEXT NOT NULL,
                type TEXT NOT NULL,
                detail TEXT,
                status TEXT NOT NULL,
                text_hash TEXT,
                threat_level TEXT,
                confidence INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 检测缓存表
        c.execute("""
            CREATE TABLE IF NOT EXISTS detect_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text_hash TEXT NOT NULL UNIQUE,
                result TEXT NOT NULL,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)

        # 威胁统计预聚合表
        c.execute("""
            CREATE TABLE IF NOT EXISTS threat_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stat_date DATE NOT NULL UNIQUE,
                total INTEGER DEFAULT 0,
                blocked INTEGER DEFAULT 0,
                passed INTEGER DEFAULT 0,
                top_threats TEXT
            )
        """)

        # 索引（IF NOT EXISTS 幂等）
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_events_time    ON events(time DESC)",
            "CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)",
            "CREATE INDEX IF NOT EXISTS idx_events_type   ON events(type)",
            "CREATE INDEX IF NOT EXISTS idx_events_hash   ON events(text_hash)",
            "CREATE INDEX IF NOT EXISTS idx_cache_hash   ON detect_cache(text_hash)",
            "CREATE INDEX IF NOT EXISTS idx_cache_expires ON detect_cache(expires_at)",
        ]:
            c.execute(idx_sql)

        conn.commit()
        conn.close()


# ── 事件 CRUD ────────────────────────────────────────────────────────────────
def add_event(event_type: str, detail: str, status: str,
              text_hash: str = None, threat_level: str = None,
              confidence: int = None):
    """
    添加事件记录，同时更新 DB 和内存缓存失效标记。
    """
    time_str = _local_now().strftime("%Y-%m-%d %H:%M:%S")
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO events (time, type, detail, status, text_hash, threat_level, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time_str, event_type, detail, status, text_hash, threat_level, confidence)
        )
        conn.commit()
        conn.close()
    # 失效事件列表缓存
    invalidate_events_cache()


def get_events_from_db(limit: int = 200, offset: int = 0,
                        status_filter: str = None,
                        type_filter: str = None,
                        date_from: str = None,
                        date_to: str = None) -> List[dict]:
    """
    从数据库查询事件列表，支持筛选。
    """
    # 尝试命中事件缓存（仅无筛选时）
    if not any([status_filter, type_filter, date_from, date_to]):
        cached = get_cached_events()
        if cached is not None:
            return cached[:limit]

    query = "SELECT time, type, detail, status, threat_level, confidence FROM events WHERE 1=1"
    params = []

    if status_filter:
        query += " AND status LIKE ?"
        params.append(f"%{status_filter}%")
    if type_filter:
        query += " AND type = ?"
        params.append(type_filter)
    if date_from:
        query += " AND time >= ?"
        params.append(date_from)
    if date_to:
        query += " AND time <= ?"
        params.append(date_to)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()

    events = [dict(r) for r in rows]

    # 缓存无筛选结果
    if not any([status_filter, type_filter, date_from, date_to]) and events:
        set_cached_events(events, ttl=30)

    return events


def get_stats() -> dict:
    """
    从 DB 聚合统计数据（利用索引加速）。
    """
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # 总数 / 拦截 / 通过
        c.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status LIKE '%拦截%' OR status LIKE '%阻断%' THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN status LIKE '%放行%' THEN 1 ELSE 0 END) AS passed
            FROM events
        """)
        row = c.fetchone()
        total   = row[0] or 0
        blocked = row[1] or 0
        passed  = row[2] or 0
        rate    = round(blocked / total * 100, 1) if total > 0 else 0

        # 近期趋势（最近 20 条）
        c.execute("""
            SELECT status FROM events ORDER BY id DESC LIMIT 20
        """)
        recent = [r[0] for r in c.fetchall()]

        conn.close()

    recent_trend = "stable"
    if len(recent) >= 10:
        recent_blocked = sum(1 for s in recent[:10]
                            if "拦截" in s or "阻断" in s)
        prev_blocked   = sum(1 for s in recent[10:20]
                            if "拦截" in s or "阻断" in s)
        if prev_blocked > 0:
            if recent_blocked > prev_blocked * 1.3:
                recent_trend = "rising"
            elif recent_blocked < prev_blocked * 0.7:
                recent_trend = "falling"

    return {
        "total":   total,
        "blocked": blocked,
        "passed":  passed,
        "block_rate": rate,
        "recent_trend": recent_trend,
    }


# ── 检测缓存 ────────────────────────────────────────────────────────────────
def get_cached_detection(text_hash: str) -> Optional[dict]:
    """查询检测缓存（DB 层）"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT result, expires_at FROM detect_cache WHERE text_hash = ?",
            (text_hash,)
        )
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        result, expires_at = row
        if expires_at:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp:
                return None
        return json.loads(result)


def set_cached_detection(text_hash: str, result: dict, ttl_seconds: int = 600):
    """写入检测缓存（DB 层）"""
    from utils.cache import detect_cache as lru_cache
    # 内存缓存
    lru_cache.set(text_hash, result)
    # DB 缓存
    expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO detect_cache (text_hash, result, expires_at)
            VALUES (?, ?, ?)
        """, (text_hash, json.dumps(result, ensure_ascii=False), expires.isoformat()))
        conn.commit()
        conn.close()


# ── 数据清理 ────────────────────────────────────────────────────────────────
def cleanup_expired_cache():
    """清理过期的检测缓存"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM detect_cache WHERE expires_at < ?",
                   (datetime.now(timezone.utc).isoformat(),))
        conn.commit()
        deleted = c.rowcount
        conn.close()
    return deleted


def cleanup_old_events(days: int = 30):
    """
    清理超过指定天数的旧事件。
    默认保留 30 天数据。
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM events WHERE time < ?", (cutoff,))
        conn.commit()
        deleted = c.rowcount
        conn.close()
    invalidate_events_cache()
    return deleted


# ── 启动时初始化 ────────────────────────────────────────────────────────────
init_db()
