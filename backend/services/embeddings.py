"""语义向量相似度 — DeepSeek Embeddings API 封装

提供：
- embed(text): 单条文本 → numpy 向量
- embed_batch(texts): 批量文本 → numpy 向量矩阵
- cosine(a, b): 余弦相似度
- best_match(query_vec, corpus_vecs, threshold): 找最相似的索引

API 失败时回退到本地哈希向量（特征降级），调用方可读取
`last_api_fallback` 判断是否降级。
"""
from __future__ import annotations
import os
import sys
import json
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np

# 父目录加入 path 以便 import config
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config


CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "_embeddings_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ── 本地回退向量 ─────────────────────────────────────────────────────────
DIM = 128


def _hash_vector(text: str, dim: int = DIM) -> np.ndarray:
    """无 API 时的本地伪 embedding：基于字符 n-gram 哈希的稳定随机向量。

    不具备真实语义能力，但能保证"完全相同的字符串→完全相同的向量"，
    在 API 不可用时仍能提供基础命中能力。
    """
    text = text.lower().strip()
    if not text:
        return np.zeros(dim, dtype=np.float32)

    vec = np.zeros(dim, dtype=np.float32)
    # 字符 2-gram 哈希
    if len(text) >= 2:
        for i in range(len(text) - 1):
            gram = text[i:i + 2]
            h = int(hashlib.md5(gram.encode("utf-8")).hexdigest()[:8], 16)
            idx = h % dim
            sign = 1.0 if (h >> 31) & 1 == 0 else -1.0
            vec[idx] += sign
    # 单字符哈希
    for ch in text:
        h = int(hashlib.md5(ch.encode("utf-8")).hexdigest()[:8], 16)
        idx = h % dim
        sign = 1.0 if (h >> 31) & 1 == 0 else -1.0
        vec[idx] += sign * 0.5

    n = np.linalg.norm(vec)
    return vec / n if n > 0 else vec


# ── 缓存管理 ──────────────────────────────────────────────────────────────
def _cache_path(key: str) -> Path:
    h = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    return CACHE_DIR / f"{h}.npy"


def _load_cache(key: str) -> Optional[np.ndarray]:
    p = _cache_path(key)
    if p.exists():
        try:
            return np.load(p)
        except Exception:
            return None
    return None


def _save_cache(key: str, vec: np.ndarray) -> None:
    try:
        np.save(_cache_path(key), vec)
    except Exception:
        pass


# ── DeepSeek Embeddings API ──────────────────────────────────────────────
_EMBEDDING_MODEL = os.environ.get("DEEPSEEK_EMBEDDING_MODEL", "deepseek-embedding")


def _call_deepseek_embeddings(texts: List[str]) -> Optional[List[List[float]]]:
    """调用 DeepSeek Embeddings 端点。返回 None 表示失败。"""
    if not config.API_KEY or config.API_PROVIDER.lower() == "local":
        return None
    try:
        import openai
        client = openai.OpenAI(
            api_key=config.API_KEY,
            base_url=config.API_BASE_URL,
            timeout=10.0,
        )
        resp = client.embeddings.create(
            model=_EMBEDDING_MODEL,
            input=texts[:20],  # 限制单批
        )
        return [d.embedding for d in resp.data]
    except Exception as e:
        # 静默失败 — 调用方根据 last_api_fallback 决定是否提示
        return None


# ── 公开 API ──────────────────────────────────────────────────────────────
def embed(text: str) -> np.ndarray:
    """获取单条文本的 embedding 向量。优先缓存。"""
    key = text.strip()
    if not key:
        return np.zeros(DIM, dtype=np.float32)

    cached = _load_cache(key)
    if cached is not None:
        return cached

    api_result = _call_deepseek_embeddings([key])
    if api_result and len(api_result) > 0:
        vec = np.array(api_result[0], dtype=np.float32)
        n = np.linalg.norm(vec)
        vec = vec / n if n > 0 else vec
        _save_cache(key, vec)
        return vec

    return _hash_vector(key)


def embed_batch(texts: List[str]) -> np.ndarray:
    """批量 embedding。"""
    if not texts:
        return np.zeros((0, DIM), dtype=np.float32)

    vecs = []
    missing_idx = []
    missing_texts = []
    for i, t in enumerate(texts):
        v = _load_cache(t.strip()) if t.strip() else None
        if v is not None:
            vecs.append((i, v))
        else:
            missing_idx.append(i)
            missing_texts.append(t)

    if missing_texts:
        api_result = _call_deepseek_embeddings(missing_texts)
        if api_result and len(api_result) == len(missing_texts):
            for j, t in enumerate(missing_texts):
                v = np.array(api_result[j], dtype=np.float32)
                n = np.linalg.norm(v)
                v = v / n if n > 0 else v
                _save_cache(t.strip(), v)
                vecs.append((missing_idx[j], v))
        else:
            for j, t in enumerate(missing_texts):
                v = _hash_vector(t.strip())
                vecs.append((missing_idx[j], v))

    vecs.sort(key=lambda x: x[0])
    return np.stack([v for _, v in vecs], axis=0)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    """两个向量的余弦相似度。"""
    na = np.linalg.norm(a)
    nb = np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def best_match(
    query_vec: np.ndarray,
    corpus_vecs: np.ndarray,
    threshold: float = 0.78,
) -> List[Tuple[int, float]]:
    """在 corpus 中找与 query 余弦相似度 ≥ threshold 的所有条目。

    返回 [(index, score), ...]，按分数降序。
    """
    if corpus_vecs.size == 0:
        return []
    qn = query_vec / (np.linalg.norm(query_vec) + 1e-9)
    cn = corpus_vecs / (np.linalg.norm(corpus_vecs, axis=1, keepdims=True) + 1e-9)
    sims = cn @ qn
    hits = [(int(i), float(s)) for i, s in enumerate(sims) if s >= threshold]
    hits.sort(key=lambda x: x[1], reverse=True)
    return hits


# ── 签名库预计算工具 ──────────────────────────────────────────────────────
def precompute_signature_embeddings(pattern_texts: List[str]) -> np.ndarray:
    """为签名库预计算 embedding。失败回退到本地。"""
    return embed_batch(pattern_texts)