"""恶意样本库服务 — 自动归档被拦截的恶意输入，支持查询、统计与导出"""
import sqlite3
import json
import hashlib
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import List, Optional

import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from runtime_paths import runtime_path

DB_PATH = runtime_path("ishield.db")
_s_lock = Lock()


def _conn():
    return sqlite3.connect(DB_PATH)


# ── 表初始化 ──────────────────────────────────────────────────────────────────
def init_samples_table():
    """创建恶意样本表（幂等）"""
    with _s_lock:
        conn = _conn()
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS malicious_samples (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                text           TEXT    NOT NULL,
                text_hash      TEXT    NOT NULL UNIQUE,
                reason         TEXT,
                category       TEXT,
                threat_level   TEXT,
                confidence     INTEGER,
                rule_hits      TEXT,
                semantic_hits  TEXT,
                source         TEXT    DEFAULT 'detect',
                detected_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_samples_hash
                ON malicious_samples(text_hash)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_samples_category
                ON malicious_samples(category)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_samples_detected_at
                ON malicious_samples(detected_at DESC)
        """)
        conn.commit()
        conn.close()


# ── 写入样本 ──────────────────────────────────────────────────────────────────
def add_sample(text: str, reason: str, category: str,
               threat_level: str, confidence: int,
               rule_hits: list, semantic_hits: dict,
               source: str = "detect") -> bool:
    """
    将一个恶意检测结果存入样本库。
    同一 text_hash 只存一次（UNIQUE 约束）。
    返回 True 表示新增，False 表示已存在。
    """
    h = hashlib.sha256(text.encode()).hexdigest()[:32]
    with _s_lock:
        conn = _conn()
        c = conn.cursor()
        try:
            c.execute("""
                INSERT INTO malicious_samples
                    (text, text_hash, reason, category, threat_level,
                     confidence, rule_hits, semantic_hits, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                text,
                h,
                reason,
                category,
                threat_level,
                confidence,
                json.dumps(rule_hits, ensure_ascii=False),
                json.dumps(semantic_hits, ensure_ascii=False),
                source,
            ))
            conn.commit()
            inserted = True
        except sqlite3.IntegrityError:
            inserted = False
        conn.close()
    return inserted


# ── 查询样本 ──────────────────────────────────────────────────────────────────
def get_samples(limit: int = 50, offset: int = 0,
               category: str = None,
               threat_level: str = None,
               min_confidence: int = None,
               date_from: str = None,
               date_to: str = None) -> List[dict]:
    """按条件查询恶意样本"""
    query = """
        SELECT id, text, text_hash, reason, category, threat_level,
               confidence, rule_hits, semantic_hits, source, detected_at
        FROM malicious_samples WHERE 1=1
    """
    params = []
    if category:
        query += " AND category = ?"
        params.append(category)
    if threat_level:
        query += " AND threat_level = ?"
        params.append(threat_level)
    if min_confidence is not None:
        query += " AND confidence >= ?"
        params.append(min_confidence)
    if date_from:
        query += " AND detected_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND detected_at <= ?"
        params.append(date_to)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with _s_lock:
        conn = _conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()

    result = []
    for r in rows:
        d = dict(r)
        d["rule_hits"]     = json.loads(d["rule_hits"]     or "[]")
        d["semantic_hits"] = json.loads(d["semantic_hits"] or "{}")
        result.append(d)
    return result


# ── 统计 ──────────────────────────────────────────────────────────────────────
def get_sample_stats() -> dict:
    """样本库统计"""
    with _s_lock:
        conn = _conn()
        c = conn.cursor()

        c.execute("""
            SELECT COUNT(*) AS total,
                   COUNT(DISTINCT category) AS category_count,
                   AVG(confidence) AS avg_confidence
            FROM malicious_samples
        """)
        row = c.fetchone()

        c.execute("""
            SELECT category, COUNT(*) AS cnt
            FROM malicious_samples
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT 10
        """)
        by_category = [{"category": r[0], "count": r[1]} for r in c.fetchall()]

        c.execute("""
            SELECT threat_level, COUNT(*) AS cnt
            FROM malicious_samples
            GROUP BY threat_level
            ORDER BY cnt DESC
        """)
        by_threat = [{"level": r[0], "count": r[1]} for r in c.fetchall()]

        c.execute("""
            SELECT DATE(detected_at) AS day, COUNT(*) AS cnt
            FROM malicious_samples
            GROUP BY DATE(detected_at)
            ORDER BY day DESC
            LIMIT 14
        """)
        by_day = [{"date": r[0], "count": r[1]} for r in c.fetchall()]

        conn.close()

    return {
        "total":          row[0] or 0,
        "category_count": row[1] or 0,
        "avg_confidence": round(row[2] or 0, 1),
        "by_category":    by_category,
        "by_threat":     by_threat,
        "by_day":        by_day,
    }


def get_categories() -> List[str]:
    """获取样本库中所有出现过的威胁类别"""
    with _s_lock:
        conn = _conn()
        c = conn.cursor()
        c.execute("""
            SELECT DISTINCT category FROM malicious_samples
            WHERE category IS NOT NULL
            ORDER BY category
        """)
        rows = [r[0] for r in c.fetchall()]
        conn.close()
    return rows


# ── 清理 ──────────────────────────────────────────────────────────────────────
def cleanup_old_samples(days: int = 90) -> int:
    """清理超过指定天数的旧样本"""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with _s_lock:
        conn = _conn()
        c = conn.cursor()
        c.execute("DELETE FROM malicious_samples WHERE detected_at < ?", (cutoff,))
        conn.commit()
        deleted = c.rowcount
        conn.close()
    return deleted


# ── 启动时初始化 ───────────────────────────────────────────────────────────────
init_samples_table()
