"""规则引擎 — 从 signatures.json 动态加载，支持热重载"""
import json
import os
import re
from threading import Lock

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
SIG_FILE = os.path.join(DATA_DIR, "signatures.json")


class SignatureManager:
    """签名管理器，支持运行时重载"""

    def __init__(self):
        self._lock = Lock()
        self._data = None
        self._load()

    def _load(self):
        """从 JSON 文件加载签名"""
        if not os.path.exists(SIG_FILE):
            self._data = {"rules": [], "sql_patterns": [], "local_semantic_patterns": [],
                          "local_roleplay_patterns": [], "local_sql_keywords": []}
            return
        with open(SIG_FILE, encoding="utf-8") as f:
            self._data = json.load(f)

    def reload(self):
        """重新加载签名（外部调用）"""
        with self._lock:
            self._load()

    @property
    def version(self):
        return self._data.get("version", "unknown")

    @property
    def rules(self):
        return [r for r in self._data.get("rules", []) if r.get("enabled", True)]

    @property
    def sql_patterns(self):
        return [p for p in self._data.get("sql_patterns", []) if p.get("enabled", True)]

    @property
    def semantic_patterns(self):
        return [p for p in self._data.get("local_semantic_patterns", []) if p.get("enabled", True)]

    @property
    def roleplay_patterns(self):
        return [p for p in self._data.get("local_roleplay_patterns", []) if p.get("enabled", True)]

    @property
    def sql_keywords(self):
        return self._data.get("local_sql_keywords", [])


# 全局单例
_sig_mgr = SignatureManager()


def get_sig_manager():
    return _sig_mgr


def rule_detect(text: str):
    """
    规则引擎检测。
    返回: (is_malicious: bool, hit_signature: str, confidence: int, all_hits: list)
    """
    text_lower = text.lower()
    hits = []

    # ── 精确签名匹配 ──────────────────────────────────────────────────
    for rule in _sig_mgr.rules:
        pat = rule["pattern"]
        if pat.lower() in text_lower:
            hits.append({
                "id":   rule["id"],
                "pattern": pat,
                "weight": rule["weight"],
                "category": rule.get("category", "未知"),
            })

    if hits:
        # 按权重排序，取最高置信度
        top = max(hits, key=lambda x: x["weight"])
        confidence = min(sum(h["weight"] for h in hits) // len(hits) + hits[0]["weight"], 100)
        confidence = min(confidence, 100)
        return True, top["pattern"], confidence, hits

    # ── SQL 模式匹配（加权组合）───────────────────────────────────────
    for pattern in _sig_mgr.sql_patterns:
        keywords_hit  = [kw for kw in pattern["keywords"]  if kw.lower() in text_lower]
        sql_ops_hit   = [op  for op  in pattern["sql_ops"] if op.lower() in text_lower]
        if keywords_hit and sql_ops_hit:
            confidence = pattern["weight"]
            return True, f"[SQL] {pattern.get('description', 'SQL组合攻击')}", confidence, [{
                "id": pattern["id"], "category": pattern.get("category", "SQL注入"),
                "keywords": keywords_hit, "sql_ops": sql_ops_hit,
                "weight": pattern["weight"],
            }]

    return False, None, 0, []


def get_signature_count() -> int:
    """返回当前启用的规则总数"""
    return len(_sig_mgr.rules) + len(_sig_mgr.semantic_patterns)
