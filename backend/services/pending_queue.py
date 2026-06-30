"""待确认工具调用队列 — DB 持久化，支持 confirm / reject / timeout 三种终态"""
import sqlite3
import uuid
import time
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Optional, List, Dict, Any

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from runtime_paths import runtime_path

DB_PATH = runtime_path("ishield_pending.db")
_db_lock = Lock()
_UTC8 = timezone(timedelta(hours=8))


def _local_now():
    return datetime.now(_UTC8)


def _now_str():
    return _local_now().strftime("%Y-%m-%d %H:%M:%S")


def _json_dumps(v):
    import json
    if v is None:
        return None
    return json.dumps(v, ensure_ascii=False, default=str)


def _json_loads(v):
    import json
    if not v:
        return {}
    try:
        return json.loads(v)
    except Exception:
        return {"raw": v}


# ── 初始化 ──────────────────────────────────────────────────────────────────
def init_db():
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS pending_calls (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                pending_id      TEXT    NOT NULL UNIQUE,
                tool_name       TEXT    NOT NULL,
                params_json     TEXT    NOT NULL,
                rule_id         TEXT,
                rule_name       TEXT,
                severity        INTEGER DEFAULT 50,
                message         TEXT,
                source_ip       TEXT,
                action          TEXT,
                chain_id        TEXT,
                token_name      TEXT,
                status          TEXT    NOT NULL DEFAULT 'pending',
                created_at      TEXT    NOT NULL,
                resolved_at     TEXT,
                resolved_by     TEXT,
                resolution      TEXT,
                ttl_seconds     INTEGER DEFAULT 300
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_calls(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_calls(created_at DESC)")
        conn.commit()
        conn.close()


# ── 创建待确认记录 ─────────────────────────────────────────────────────────────
def create_pending(
    tool_name: str,
    params: Dict[str, Any],
    rule_id: str = None,
    rule_name: str = None,
    severity: int = 50,
    message: str = "",
    source_ip: str = None,
    action: str = None,
    chain_id: str = None,
    token_name: str = None,
    ttl_seconds: int = 300,
) -> str:
    """将一个需要确认的工具调用加入待确认队列，返回 pending_id"""
    pending_id = str(uuid.uuid4())[:8]
    now = _now_str()
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO pending_calls
            (pending_id, tool_name, params_json, rule_id, rule_name, severity,
             message, source_ip, action, chain_id, token_name, status,
             created_at, ttl_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """, (
            pending_id, tool_name, _json_dumps(params), rule_id, rule_name,
            severity, message, source_ip, action, chain_id, token_name, now, ttl_seconds
        ))
        conn.commit()
        conn.close()
    return pending_id


# ── 查询 ─────────────────────────────────────────────────────────────────────
def get_pending(pending_id: str) -> Optional[dict]:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT * FROM pending_calls WHERE pending_id = ? AND status = 'pending'",
            (pending_id,)
        )
        row = c.fetchone()
        conn.close()
    if not row:
        return None
    return _row_to_dict(row)


def list_pending(limit: int = 100, status: str = "pending") -> List[dict]:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if status == "all":
            c.execute(
                "SELECT * FROM pending_calls ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        else:
            c.execute(
                "SELECT * FROM pending_calls WHERE status = ? ORDER BY id DESC LIMIT ?",
                (status, limit)
            )
        rows = c.fetchall()
        conn.close()
    return [_row_to_dict(r) for r in rows]


def get_pending_count(status: str = "pending") -> int:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT COUNT(*) FROM pending_calls WHERE status = ?",
            (status,)
        )
        count = c.fetchone()[0]
        conn.close()
    return count


# ── 解决（confirm / reject / timeout） ────────────────────────────────────────
def resolve_pending(
    pending_id: str,
    resolution: str,   # "confirmed" | "rejected" | "timeout"
    resolved_by: str = "admin",
) -> Optional[dict]:
    """将 pending_id 标记为已解决，返回解决前的完整记录（含 params）。"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT * FROM pending_calls WHERE pending_id = ? AND status = 'pending'",
            (pending_id,)
        )
        row = c.fetchone()
        if not row:
            conn.close()
            return None

        record = _row_to_dict(row)
        c.execute(
            "UPDATE pending_calls SET status = ?, resolved_at = ?, resolved_by = ?, resolution = ? "
            "WHERE pending_id = ?",
            (resolution, _now_str(), resolved_by, resolution, pending_id)
        )
        conn.commit()
        conn.close()
    return record


def expire_pending():
    """自动过期超时的待确认记录"""
    now_ts = time.time()
    expired = 0
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT id, created_at, ttl_seconds FROM pending_calls WHERE status = 'pending'"
        )
        for row in c.fetchall():
            pending_id, created_at_str, ttl = row
            try:
                created = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S").timestamp()
                if now_ts - created > (ttl or 300):
                    c.execute(
                        "UPDATE pending_calls SET status = 'timeout', resolved_at = ?, "
                        "resolution = 'timeout' WHERE id = ?",
                        (_now_str(), pending_id)
                    )
                    expired += 1
            except Exception:
                pass
        conn.commit()
        conn.close()
    return expired


# ── 统计 ─────────────────────────────────────────────────────────────────────
def get_pending_stats() -> dict:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT status, COUNT(*) as cnt FROM pending_calls GROUP BY status
        """)
        status_counts = {r[0]: r[1] for r in c.fetchall()}

        c.execute("""
            SELECT COUNT(*) FROM pending_calls
            WHERE status = 'pending'
            AND created_at >= datetime('now', '-1 hour')
        """)
        last_hour = c.fetchone()[0] or 0

        c.execute("SELECT COUNT(*) FROM pending_calls WHERE status = 'confirmed'")
        confirmed = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM pending_calls WHERE status = 'rejected'")
        rejected = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM pending_calls WHERE status = 'timeout'")
        timed_out = c.fetchone()[0] or 0
        conn.close()

    total_resolved = confirmed + rejected + timed_out
    confirm_rate = round(confirmed / total_resolved * 100, 1) if total_resolved > 0 else 0

    return {
        "pending": status_counts.get("pending", 0),
        "confirmed": confirmed,
        "rejected": rejected,
        "timeout": timed_out,
        "total_resolved": total_resolved,
        "confirm_rate": confirm_rate,
        "last_hour": last_hour,
    }


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["params"] = _json_loads(d.pop("params_json", "{}"))
    return d


init_db()
