"""事件存储服务 — SQLite + 内存缓存双写，检测缓存，DB 索引，攻击链审计"""
import sqlite3
import json
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import List, Optional, Dict, Any
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from runtime_paths import runtime_path
from utils.cache import detect_cache, invalidate_events_cache, get_cached_events, set_cached_events

DB_PATH = runtime_path("ishield.db")
_db_lock = Lock()

_UTC8 = timezone(timedelta(hours=8))


STATUS_LABELS = {
    "blocked": "已阻断",
    "confirm": "需确认",
    "allowed": "已放行",
    "running": "处理中",
    "error": "异常",
    "review": "已评估",
    "unknown": "未知",
}


def _local_now():
    return datetime.now(_UTC8)


def _json_dumps(value: Optional[Dict[str, Any]]) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, default=str)


def _json_loads(value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {"raw": value}


def normalize_status(status: str = "", stage: str = "", metadata: Dict[str, Any] = None) -> str:
    """Map old Chinese labels and new runtime decisions into stable status codes."""
    raw = f"{status or ''} {stage or ''}".lower()
    meta = metadata or {}
    decision = str(meta.get("decision") or meta.get("runtime_status") or meta.get("status_code") or "").lower()
    if decision in {"blocked", "confirm", "allowed", "running", "error", "review", "timeout"}:
        return "error" if decision == "timeout" else decision
    if any(k in raw for k in ["阻断", "拦截", "拒绝", "blocked", "deny", "policy_blocked", "detection_blocked"]):
        return "blocked"
    if any(k in raw for k in ["需确认", "确认", "pending", "confirm", "policy_confirm"]):
        return "confirm"
    if any(k in raw for k in ["异常", "失败", "出错", "超时", "error", "timeout", "failed"]):
        return "error"
    if any(k in raw for k in ["放行", "通过", "完成", "成功", "executed", "mock", "allowed", "passed", "tool_finished"]):
        return "allowed"
    if any(k in raw for k in ["分析中", "执行中", "running", "started", "request_received"]):
        return "running"
    if any(k in raw for k in ["已评估", "评估", "review", "policy_evaluated"]):
        return "review"
    return "unknown"


def status_label(status_code: str) -> str:
    return STATUS_LABELS.get(status_code or "unknown", STATUS_LABELS["unknown"])


def normalize_event(item: Dict[str, Any]) -> Dict[str, Any]:
    metadata = item.get("metadata") or {}
    status_code = normalize_status(item.get("status"), item.get("stage"), metadata)
    item["status_code"] = status_code
    item["status_label"] = status_label(status_code)
    item["disposition"] = status_code
    if isinstance(metadata, dict):
        metadata.setdefault("status_code", status_code)
        item["metadata"] = metadata
    return item


def _row_to_event(row) -> Dict[str, Any]:
    item = dict(row)
    item["metadata"] = _json_loads(item.pop("metadata_json", None))
    return normalize_event(item)


# ── 初始化 ──────────────────────────────────────────────────────────────────
def init_db():
    """初始化数据库，创建表和索引（幂等操作）"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # ── 建表（IF NOT EXISTS 不改变已有表）──────────────────────────
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
                source_ip TEXT,
                action TEXT,
                tool_name TEXT,
                target TEXT,
                rule_id TEXT,
                category TEXT,
                metadata_json TEXT,
                chain_id TEXT,
                stage TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS detect_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text_hash TEXT NOT NULL UNIQUE,
                result TEXT NOT NULL,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)

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

        # ── 迁移：确保所有新列都存在（兼容已有旧数据库）───────────────
        existing_columns = set()
        try:
            for row in c.execute("PRAGMA table_info(events)").fetchall():
                existing_columns.add(row[1])
        except Exception:
            pass

        for col_name, col_def in [
            ("text_hash",      "TEXT"),
            ("threat_level",   "TEXT"),
            ("confidence",     "INTEGER"),
            ("source_ip",      "TEXT"),
            ("action",         "TEXT"),
            ("tool_name",      "TEXT"),
            ("target",         "TEXT"),
            ("rule_id",        "TEXT"),
            ("category",       "TEXT"),
            ("metadata_json",  "TEXT"),
            ("chain_id",       "TEXT"),
            ("stage",          "TEXT"),
        ]:
            if col_name not in existing_columns:
                try:
                    c.execute(f"ALTER TABLE events ADD COLUMN {col_name} {col_def}")
                except sqlite3.OperationalError:
                    pass

        # ── 建索引（每个独立 try，防止列不存在时报错）────────────────
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC)",
            "CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)",
        ]:
            try:
                c.execute(idx_sql)
            except sqlite3.OperationalError:
                pass

        # text_hash 索引（可能列刚被 ALTER 添加）
        if "text_hash" in existing_columns or True:
            try:
                c.execute("CREATE INDEX IF NOT EXISTS idx_events_hash ON events(text_hash)")
            except sqlite3.OperationalError:
                pass

        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_tool_name ON events(tool_name)",
            "CREATE INDEX IF NOT EXISTS idx_events_category ON events(category)",
            "CREATE INDEX IF NOT EXISTS idx_events_chain_id ON events(chain_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_stage ON events(stage)",
            "CREATE INDEX IF NOT EXISTS idx_cache_hash ON detect_cache(text_hash)",
            "CREATE INDEX IF NOT EXISTS idx_cache_expires ON detect_cache(expires_at)",
        ]:
            try:
                c.execute(idx_sql)
            except sqlite3.OperationalError:
                pass

        conn.commit()
        conn.close()


# ── 事件 CRUD ────────────────────────────────────────────────────────────────
def add_event(event_type: str, detail: str, status: str,
              text_hash: str = None, threat_level: str = None,
              confidence: int = None, source_ip: str = None,
              action: str = None, tool_name: str = None,
              target: str = None, rule_id: str = None,
              category: str = None, metadata: Dict[str, Any] = None,
              chain_id: str = None, stage: str = None):
    """添加事件记录，同时更新 DB 和内存缓存失效标记。"""
    time_str = _local_now().strftime("%Y-%m-%d %H:%M:%S")
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT INTO events (time, type, detail, status, text_hash, threat_level, confidence, source_ip, action, tool_name, target, rule_id, category, metadata_json, chain_id, stage) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                time_str, event_type, detail, status, text_hash, threat_level, confidence,
                source_ip, action, tool_name, target, rule_id, category, _json_dumps(metadata),
                chain_id, stage
            )
        )
        event_id = c.lastrowid
        conn.commit()
        conn.close()
    invalidate_events_cache()
    return event_id


def get_events_from_db(limit: int = 200, offset: int = 0,
                        status_filter: str = None,
                        type_filter: str = None,
                        date_from: str = None,
                        date_to: str = None,
                        chain_id: str = None) -> List[dict]:
    """从数据库查询事件列表，支持筛选。"""
    use_cache = not any([status_filter, type_filter, date_from, date_to, chain_id])
    if use_cache:
        cached = get_cached_events()
        if cached is not None:
            return [normalize_event(dict(item)) for item in cached[offset: offset + limit]]

    normalized_status_filter = None
    if status_filter and str(status_filter).lower() in {"blocked", "allowed", "confirm", "running", "error", "review"}:
        normalized_status_filter = str(status_filter).lower()
        status_filter = None

    query = (
        "SELECT id, time, type, detail, status, threat_level, confidence, source_ip, action, "
        "tool_name, target, rule_id, category, metadata_json, chain_id, stage FROM events WHERE 1=1"
    )
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
    if chain_id:
        query += " AND chain_id = ?"
        params.append(chain_id)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()

    events = []
    for row in rows:
        events.append(_row_to_event(row))

    if normalized_status_filter:
        events = [event for event in events if event.get("status_code") == normalized_status_filter]

    if use_cache and events:
        set_cached_events(events, ttl=30)

    return events


def get_event_detail(event_id: int) -> Optional[dict]:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT id, time, type, detail, status, text_hash, threat_level, confidence, source_ip, action, tool_name, target, rule_id, category, metadata_json, chain_id, stage "
            "FROM events WHERE id = ?",
            (event_id,),
        )
        row = c.fetchone()
        conn.close()

    if not row:
        return None

    return _row_to_event(row)


def get_chain_events(chain_id: str) -> List[dict]:
    if not chain_id:
        return []

    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT id, time, type, detail, status, text_hash, threat_level, confidence, source_ip, action, tool_name, target, rule_id, category, metadata_json, chain_id, stage "
            "FROM events WHERE chain_id = ? ORDER BY id ASC",
            (chain_id,),
        )
        rows = c.fetchall()
        conn.close()

    chain_events = []
    for row in rows:
        chain_events.append(_row_to_event(row))
    return chain_events


def get_chain_summary(limit: int = 50) -> List[dict]:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """
            SELECT id, time, type, detail, status, threat_level, confidence, source_ip,
                   action, tool_name, target, rule_id, category, metadata_json, chain_id, stage
            FROM events
            WHERE chain_id IS NOT NULL AND chain_id != ''
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(limit * 80, limit),),
        )
        rows = c.fetchall()
        conn.close()

    grouped = {}
    for row in rows:
        event = _row_to_event(row)
        cid = event.get("chain_id")
        if not cid:
            continue
        grouped.setdefault(cid, []).append(event)
        if len(grouped) >= limit and all(len(v) >= 2 for v in grouped.values()):
            continue

    summaries = []
    for cid, events in list(grouped.items())[:limit]:
        ordered = sorted(events, key=lambda e: e.get("id") or 0)
        status_codes = {e.get("status_code") for e in ordered}
        if "blocked" in status_codes:
            status_code = "blocked"
        elif "confirm" in status_codes:
            status_code = "confirm"
        elif "error" in status_codes:
            status_code = "error"
        elif "running" in status_codes:
            status_code = "running"
        else:
            status_code = "allowed"
        first = ordered[0]
        last = ordered[-1]
        summaries.append({
            "chain_id": cid,
            "started_at": first.get("time"),
            "ended_at": last.get("time"),
            "event_count": len(ordered),
            "max_confidence": max((e.get("confidence") or 0) for e in ordered),
            "blocked": 1 if status_code == "blocked" else 0,
            "requires_confirmation": 1 if status_code == "confirm" else 0,
            "source_ip": last.get("source_ip") or first.get("source_ip"),
            "action": last.get("action") or first.get("action"),
            "tool_name": last.get("tool_name") or first.get("tool_name"),
            "target": last.get("target") or first.get("target"),
            "stages": [e.get("stage") or e.get("type") for e in ordered],
            "status": status_label(status_code),
            "status_code": status_code,
            "disposition": status_code,
        })
    return summaries


def get_stats() -> dict:
    """从 DB 聚合统计数据（利用索引加速）。"""
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("SELECT status, threat_level, chain_id, stage, metadata_json, time FROM events")
        rows = c.fetchall()
        normalized = [
            normalize_status(row[0], row[3], _json_loads(row[4]))
            for row in rows
        ]
        total = len(rows)
        blocked = sum(1 for code in normalized if code == "blocked")
        passed = sum(1 for code in normalized if code == "allowed")
        high_risk = sum(1 for row in rows if row[1] in ("high", "critical"))
        rate = round(blocked / total * 100, 1) if total > 0 else 0

        today_str = _local_now().strftime("%Y-%m-%d")
        today_rows = [row for row in rows if str(row[5] or "").startswith(today_str)]
        today_total = len(today_rows)
        today_blocked = sum(1 for row in today_rows if normalize_status(row[0], row[3], _json_loads(row[4])) == "blocked")

        c.execute("SELECT status, stage, metadata_json FROM events ORDER BY id DESC LIMIT 20")
        recent = [normalize_status(r[0], r[1], _json_loads(r[2])) for r in c.fetchall()]
        c.execute("SELECT COUNT(DISTINCT chain_id) FROM events WHERE chain_id IS NOT NULL AND chain_id != ''")
        chain_total_row = c.fetchone()
        chain_total = chain_total_row[0] or 0
        conn.close()

    recent_trend = "stable"
    if len(recent) >= 10:
        recent_blocked = sum(1 for s in recent[:10] if s == "blocked")
        prev_blocked = sum(1 for s in recent[10:20] if s == "blocked")
        if prev_blocked > 0:
            if recent_blocked > prev_blocked * 1.3:
                recent_trend = "rising"
            elif recent_blocked < prev_blocked * 0.7:
                recent_trend = "falling"

    return {
        "total": total,
        "blocked": blocked,
        "passed": passed,
        "block_rate": rate,
        "recent_trend": recent_trend,
        "high_risk": high_risk,
        "today_total": today_total,
        "today_blocked": today_blocked,
        "chain_total": chain_total,
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
    lru_cache.set(text_hash, result)
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
    """清理超过指定天数的旧事件。"""
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


init_db()
