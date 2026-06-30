"""规则引擎 — 从 signatures.json 动态加载，支持热重载 + 4 策略匹配"""
import json
import os
import re
from threading import Lock
from typing import List, Dict, Tuple, Optional

from runtime_paths import backend_data_dir

DATA_DIR = backend_data_dir()
SIG_FILE = DATA_DIR / "signatures.json"


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


# ── 4 策略匹配权重 ─────────────────────────────────────────────────────────
W_EXACT = 0.4
W_NORMALIZED = 0.3
W_FUZZY = 0.2
W_SEMANTIC = 0.1


def _match_one(text_raw: str, text_lower: str, text_normalized: str,
               pattern: str,
               text_emb: Optional[List[float]] = None) -> List[Dict]:
    """对单条规则做 4 策略匹配，返回所有命中的 hit 列表。

    text_emb: 预计算的输入文本 embedding（避免每条规则重复调用 embed API）。
    """
    from services.text_normalize import (
        normalize_zero_width,
        normalize_homoglyph,
        levenshtein_match_anywhere,
    )
    from services.embeddings import (
        precompute_signature_embeddings,
        embed,
        cosine,
        best_match,
    )
    import config
    import numpy as np

    hits = []
    pat_lower = pattern.lower()

    # ── 1. 精确子串匹配（权重 0.4）─────────────────────────────
    if pat_lower in text_lower:
        score = W_EXACT
        hits.append({
            "rule_id": "",
            "pattern": pattern,
            "matched_text": pattern,
            "match_strategy": "exact",
            "score_contribution": score,
            "match_start": text_lower.find(pat_lower),
            "match_end": text_lower.find(pat_lower) + len(pat_lower),
        })

    # ── 2. 归一化匹配（权重 0.3）─────────────────────────────
    norm_text = text_normalized  # 已归一化
    norm_pat = normalize_homoglyph(pattern).lower()
    if norm_pat and norm_pat in norm_text and not any(
        h["match_strategy"] == "exact" for h in hits
    ):
        score = W_NORMALIZED
        pos = norm_text.find(norm_pat)
        hits.append({
            "rule_id": "",
            "pattern": pattern,
            "matched_text": pattern,
            "match_strategy": "normalized",
            "score_contribution": score,
            "match_start": pos,
            "match_end": pos + len(norm_pat),
        })

    # ── 3. 模糊编辑距离匹配（权重 0.2）─────────────────────────
    if len(pattern) >= 4 and levenshtein_match_anywhere(text_raw, pattern, max_dist=2):
        if not any(h["match_strategy"] in ("exact", "normalized") for h in hits):
            score = W_FUZZY
            hits.append({
                "rule_id": "",
                "pattern": pattern,
                "matched_text": pattern,
                "match_strategy": "fuzzy",
                "score_contribution": score,
                "match_start": 0,
                "match_end": len(pattern),
            })

    # ── 4. 语义向量相似度（权重 0.1）──────────────────────────
    # text_emb 已预计算（rule_detect 层统一调一次），避免 N 条规则重复调用 embed
    # 仅当 USE_EMBEDDING_STRATEGY=True 且 text_emb 有效时才执行
    if text_emb is not None and getattr(config, "USE_EMBEDDING_STRATEGY", False):
        try:
            pv = embed(pattern)      # 每条规则只算一次 pattern embedding（cache 里已有）
            sim = cosine(text_emb, pv)
            threshold = getattr(config, "EMBEDDING_SIM_THRESHOLD", 0.78)
            if sim >= threshold:
                # 仅当其他策略都没命中时，记为 semantic 主命中
                if not any(h["match_strategy"] in ("exact", "normalized", "fuzzy") for h in hits):
                    hits.append({
                        "rule_id": "",
                        "pattern": pattern,
                        "matched_text": pattern,
                        "match_strategy": "semantic",
                        "score_contribution": W_SEMANTIC * (sim / threshold),
                        "match_start": 0,
                        "match_end": len(pattern),
                        "similarity": sim,
                    })
                else:
                    # 作为补充加权（不独立成 hit）
                    for h in hits:
                        if h["match_strategy"] in ("exact", "normalized", "fuzzy"):
                            h["score_contribution"] += W_SEMANTIC * (sim / threshold) * 0.3
        except Exception:
            pass

    return hits


def rule_detect(text: str) -> Tuple[bool, str, int, List[dict]]:
    """规则引擎检测 — 4 策略匹配。

    返回: (is_malicious, hit_signature, confidence, all_hits)
        all_hits: list of {
            "rule_id": str,
            "category": str,
            "weight": float,
            "matched_text": str,
            "match_strategy": str,
            "score_contribution": float,
            "match_start": int,
            "match_end": int,
        }
    """
    from services.text_normalize import normalize_zero_width, normalize_homoglyph
    from services.embeddings import embed
    import random
    import config

    text_lower = text.lower()
    text_normalized = normalize_homoglyph(normalize_zero_width(text_lower))
    all_hits: List[dict] = []

    # 预计算输入文本的 embedding（所有规则共享，避免重复 API 调用）
    # 仅在语义策略启用时才计算
    text_emb = None
    if getattr(config, "USE_EMBEDDING_STRATEGY", False):
        try:
            text_emb = embed(text)
        except Exception:
            pass

    # ── 精确签名匹配（4 策略）───────────────────────────────
    for rule in _sig_mgr.rules:
        pat = rule["pattern"]
        hit_list = _match_one(text, text_lower, text_normalized, pat, text_emb=text_emb)
        for h in hit_list:
            h["rule_id"] = rule["id"]
            h["category"] = rule.get("category", "未知")
            h["weight"] = float(rule.get("weight", 25)) / 100.0  # 归一化到 0-1
            all_hits.append(h)

    # ── SQL 模式匹配（加权组合）───────────────────────────────
    sql_hits = []
    for pattern in _sig_mgr.sql_patterns:
        keywords_hit = [kw for kw in pattern["keywords"] if kw.lower() in text_lower]
        sql_ops_hit = [op for op in pattern["sql_ops"] if op.lower() in text_lower]
        if keywords_hit and sql_ops_hit:
            sql_hits.append({
                "rule_id": pattern["id"],
                "category": pattern.get("category", "SQL注入"),
                "matched_text": f"[SQL] {pattern.get('description', 'SQL组合攻击')}",
                "match_strategy": "exact",
                "score_contribution": float(pattern["weight"]) / 100.0,
                "match_start": 0,
                "match_end": 0,
                "weight": float(pattern["weight"]) / 100.0,
                "keywords": keywords_hit,
                "sql_ops": sql_ops_hit,
            })

    # 计算置信度
    if all_hits or sql_hits:
        combined_hits = all_hits + sql_hits
        # 加权融合：每条 hit 的 score_contribution（0-1）× rule_weight（0-1）
        # 归一化到 0-100，去魔数封顶
        total_score = sum(h.get("score_contribution", 0) for h in combined_hits)
        max_rule_weight = max(
            (h.get("weight", 0.5) for h in combined_hits),
            default=0.5,
        )
        # 设计：单条 exact 命中 + weight=0.25 → base_point ≈ 40
        # 多条 exact 命中 + weight=0.25 → base_point 接近 70+
        # 高 weight 单条命中（0.5）→ base_point ≈ 80
        base_point = total_score * 100.0 + max_rule_weight * 30.0
        base_point = max(15.0, min(base_point, 100.0))

        # 加入高斯噪声 σ=2.5
        noisy = base_point + random.gauss(0, 2.5)
        confidence = max(0, min(100, int(round(noisy))))

        # top hit 作为 reason 字段
        top = max(combined_hits, key=lambda h: h.get("score_contribution", 0))
        hit_signature = top.get("matched_text", top.get("pattern", ""))

        return True, hit_signature, confidence, combined_hits

    return False, None, 0, []


def get_signature_count() -> int:
    """返回当前启用的规则总数"""
    return len(_sig_mgr.rules) + len(_sig_mgr.semantic_patterns)