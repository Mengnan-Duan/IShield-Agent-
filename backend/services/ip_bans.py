"""IP 封禁持久化 — 与 ishield.db 共享连接（复用 events.py 的 DB）"""
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import List, Optional

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from runtime_paths import runtime_path

DB_PATH = runtime_path("ishield.db")
_db_lock = Lock()
_UTC8 = timezone(timedelta(hours=8))


def _now_str():
    return datetime.now(_UTC8).strftime("%Y-%m-%d %H:%M:%S")


def _utcnow():
    return datetime.now(_UTC8)


def _init_ban_table():
    """创建 ip_bans 表（如不存在）"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS ip_bans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip              TEXT    NOT NULL,
                reason          TEXT,
                banned_at       TEXT    NOT NULL,
                ban_until       REAL    NOT NULL,
                score_at_ban    INTEGER DEFAULT 0,
                released_at     TEXT,
                is_active      INTEGER DEFAULT 1,
                UNIQUE(ip)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_bans_ip ON ip_bans(ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_bans_until ON ip_bans(ban_until)")
        conn.commit()
        conn.close()


def ban_ip(ip: str, reason: str = "", duration_seconds: int = 300, score_at_ban: int = 0) -> bool:
    """封禁一个 IP，写入 DB，返回是否成功（False 表示已存在）"""
    ban_until = time.time() + duration_seconds
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO ip_bans
            (ip, reason, banned_at, ban_until, score_at_ban, released_at, is_active)
            VALUES (?, ?, ?, ?, ?, NULL, 1)
        """, (ip, reason, _now_str(), ban_until, score_at_ban))
        conn.commit()
        affected = c.rowcount
        conn.close()
    return affected > 0


def unban_ip(ip: str) -> bool:
    """手动解封 IP"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            UPDATE ip_bans SET is_active = 0, released_at = ? WHERE ip = ? AND is_active = 1
        """, (_now_str(), ip))
        conn.commit()
        affected = c.rowcount
        conn.close()
    return affected > 0


def is_banned_db(ip: str) -> bool:
    """查询 DB 中 IP 是否在封禁期内"""
    now = time.time()
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT ban_until FROM ip_bans WHERE ip = ? AND is_active = 1 AND ban_until > ?",
            (ip, now)
        )
        row = c.fetchone()
        conn.close()
    return row is not None


def get_ban_info(ip: str) -> Optional[dict]:
    """获取 IP 的封禁信息"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT * FROM ip_bans WHERE ip = ? AND is_active = 1 ORDER BY id DESC LIMIT 1",
            (ip,)
        )
        row = c.fetchone()
        conn.close()
    if not row:
        return None
    d = dict(row)
    d["is_expired"] = time.time() > d["ban_until"]
    return d


def get_active_bans(limit: int = 100) -> List[dict]:
    """获取当前所有有效封禁"""
    now = time.time()
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT * FROM ip_bans WHERE is_active = 1 AND ban_until > ? ORDER BY ban_until ASC LIMIT ?",
            (now, limit)
        )
        rows = c.fetchall()
        conn.close()
    return [dict(r) for r in rows]


def cleanup_expired_bans() -> int:
    """清理已过期的封禁记录（标记为非活跃）"""
    now = time.time()
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "UPDATE ip_bans SET is_active = 0, released_at = ? WHERE is_active = 1 AND ban_until <= ?",
            (_now_str(), now)
        )
        conn.commit()
        affected = c.rowcount
        conn.close()
    return affected


def get_ban_count() -> dict:
    """封禁统计"""
    now = time.time()
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM ip_bans WHERE is_active = 1 AND ban_until > ?", (now,))
        active = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM ip_bans")
        total = c.fetchone()[0] or 0
        conn.close()
    return {"active": active, "total": total}


_init_ban_table()
