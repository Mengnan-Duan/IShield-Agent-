"""
Operation-level audit log service.
Records every API request with token identity, IP, endpoint, and result.
Corresponds to Article 6: Decision authority accountability.
"""
import sqlite3
import json
import time
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

DB_PATH = Path(__file__).parent.parent / "ishield_audit.db"
_db_lock = threading.Lock()

_UTC8 = timezone(timedelta(hours=8))


def _local_now():
    return datetime.now(_UTC8)


def _init_db():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            token_name TEXT,
            role TEXT,
            ip TEXT,
            method TEXT,
            path TEXT NOT NULL,
            request_id TEXT,
            threat_level TEXT DEFAULT 'none',
            status_code INTEGER,
            elapsed_ms REAL,
            request_size INTEGER DEFAULT 0,
            user_agent TEXT,
            chain_id TEXT,
            action_tag TEXT,
            detail TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_token ON audit_log(token_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_chain ON audit_log(chain_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ip ON audit_log(ip)")
    conn.commit()
    conn.close()


def log_operation(
    token_meta: Optional[dict],
    request,
    response,
    elapsed_ms: float,
    chain_id: Optional[str] = None,
    action_tag: Optional[str] = None,
    detail: Optional[str] = None,
    threat_level: str = "none",
) -> None:
    ts = _local_now().isoformat()
    if token_meta is None:
        token_meta = {"name": "anonymous", "role": "guest"}

    ip = _get_client_ip(request)
    status_code = getattr(response, "status_code", None) if response else None

    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    try:
        conn.execute("""
            INSERT INTO audit_log
            (timestamp, token_name, role, ip, method, path, request_id,
             threat_level, status_code, elapsed_ms, request_size, user_agent,
             chain_id, action_tag, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts,
            token_meta.get("name", "unknown"),
            token_meta.get("role", "unknown"),
            ip,
            request.method,
            request.path,
            getattr(request, "_request_id", None),
            threat_level,
            status_code,
            elapsed_ms,
            int(request.content_length or 0),
            (request.headers.get("User-Agent", "") or "")[:200],
            chain_id,
            action_tag,
            detail,
        ))
        conn.commit()
    finally:
        conn.close()


def query_audit(
    token: Optional[str] = None,
    ip: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> Dict[str, Any]:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        where = ["1=1"]
        params: list = []
        if token:
            where.append("token_name = ?")
            params.append(token)
        if ip:
            where.append("ip = ?")
            params.append(ip)
        if start:
            where.append("timestamp >= ?")
            params.append(start)
        if end:
            where.append("timestamp <= ?")
            params.append(end)
        if action:
            where.append("action_tag = ?")
            params.append(action)

        where_clause = " AND ".join(where)
        cursor = conn.execute(
            f"SELECT * FROM audit_log WHERE {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        )
        rows = [dict(r) for r in cursor.fetchall()]
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM audit_log WHERE {where_clause}", params
        ).fetchone()
        total = total_row[0] if total_row else 0
        return {"logs": rows, "total": total, "limit": limit, "offset": offset}
    finally:
        conn.close()


def get_audit_summary(days: int = 7) -> Dict[str, Any]:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        cutoff = (datetime.now(_UTC8) - timedelta(days=days)).isoformat()

        top_tokens = conn.execute("""
            SELECT token_name, role, COUNT(*) as count,
                   SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
            FROM audit_log WHERE timestamp >= ? GROUP BY token_name ORDER BY count DESC LIMIT 10
        """, (cutoff,)).fetchall()

        top_ips = conn.execute("""
            SELECT ip, COUNT(*) as count,
                   SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
            FROM audit_log WHERE timestamp >= ? GROUP BY ip ORDER BY count DESC LIMIT 10
        """, (cutoff,)).fetchall()

        top_endpoints = conn.execute("""
            SELECT path, method, COUNT(*) as count
            FROM audit_log WHERE timestamp >= ?
            GROUP BY path, method ORDER BY count DESC LIMIT 10
        """, (cutoff,)).fetchall()

        high_risk = conn.execute("""
            SELECT action_tag, COUNT(*) as count
            FROM audit_log WHERE timestamp >= ? AND threat_level IN ('high','critical')
            GROUP BY action_tag ORDER BY count DESC
        """, (cutoff,)).fetchall()

        daily = conn.execute("""
            SELECT DATE(timestamp) as day, COUNT(*) as count
            FROM audit_log WHERE timestamp >= ?
            GROUP BY day ORDER BY day
        """, (cutoff,)).fetchall()

        return {
            "period_days": days,
            "cutoff": cutoff,
            "top_tokens": [dict(r) for r in top_tokens],
            "top_ips": [dict(r) for r in top_ips],
            "top_endpoints": [dict(r) for r in top_endpoints],
            "high_risk_actions": [dict(r) for r in high_risk],
            "daily_volume": [dict(r) for r in daily],
        }
    finally:
        conn.close()


def _get_client_ip(request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    demo = request.headers.get("X-Demo-Source-IP", "").strip()
    if demo:
        return demo.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


_init_db()
