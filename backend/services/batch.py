"""批量检测服务"""
import uuid
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import hashlib

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.detection import hybrid_detect
from services.events import get_cached_detection, set_cached_detection

# 内存中的批量任务状态
_batch_tasks = {}  # task_id -> {status, results, created_at}
_batch_lock = __import__("threading").Lock()


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def batch_detect_sync(texts: List[str], task_id: str = None) -> dict:
    """
    同步批量检测（串行，后端内部并发处理）。
    返回批量结果，不改变 API 响应格式。
    """
    if task_id is None:
        task_id = str(uuid.uuid4())[:16]

    results = []
    for text in texts:
        h = text_hash(text)

        # 先查缓存
        cached = get_cached_detection(h)
        if cached:
            results.append({**cached, "cached": True})
            continue

        # 执行检测
        is_mal, reason, conf = hybrid_detect(text, use_cache=True)
        res = {
            "status":       "malicious" if is_mal else "safe",
            "reason":       reason if is_mal else "",
            "confidence":    conf,
            "text_preview": text[:80] + ("..." if len(text) > 80 else ""),
            "cached":       False,
        }
        # 写入缓存
        set_cached_detection(h, res)
        results.append(res)

    # 统计
    malicious = sum(1 for r in results if r["status"] == "malicious")
    safe      = sum(1 for r in results if r["status"] == "safe")

    return {
        "task_id": task_id,
        "total":   len(texts),
        "malicious": malicious,
        "safe":     safe,
        "results":  results,
    }
