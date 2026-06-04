"""混合检测核心逻辑 — 规则 + 语义并行检测"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple

from services.rule_engine import rule_detect, get_sig_manager
from services.semantic import semantic_detect, semantic_detect_local

DetectionResult = Tuple[bool, str, dict]  # (is_malicious, reason, confidence_data)


def hybrid_detect(text: str, use_cache: bool = True) -> DetectionResult:
    """
    混合检测主入口。

    规则检测（CPU 密集）和语义检测（I/O 密集）并行执行以提升性能。
    权重融合：rule × 0.4 + semantic × 0.6

    参数:
        text: 待检测文本
        use_cache: 是否启用缓存

    返回:
        (is_malicious, reason, {
            rule: {...},
            semantic: {...},
            combined: int,
            api_fallback: bool,
            threat_level: str,  # none / low / medium / high
            detection_time_ms: float
        })
    """
    import time
    start = time.time()

    # ── 并行执行两个检测引擎 ─────────────────────────────────────────
    rule_result     = None
    semantic_result = None
    api_fallback    = False

    def run_rule():
        return rule_detect(text)

    def run_semantic():
        try:
            return semantic_detect(text)
        except Exception:
            return semantic_detect_local(text)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_rule  = pool.submit(run_rule)
        f_sem   = pool.submit(run_semantic)

        try:
            rule_alert, rule_hit, rule_conf, rule_hits = f_rule.result(timeout=10)
        except Exception:
            rule_alert, rule_hit, rule_conf, rule_hits = False, None, 0, []

        try:
            semantic_alert, semantic_conf = f_sem.result(timeout=20)
        except Exception:
            semantic_alert, semantic_conf = False, 0
            api_fallback = True

    # ── 综合判定 ────────────────────────────────────────────────────
    reasons = []
    if rule_alert:
        reasons.append(f"规则命中: {rule_hit}")
    if semantic_alert:
        reasons.append("语义判定: 恶意")

    overall = rule_alert or semantic_alert

    # 加权融合
    combined_confidence = 0
    if (rule_confidence := rule_conf) > 0 and semantic_conf > 0:
        combined_confidence = int(rule_conf * 0.4 + semantic_conf * 0.6)
    elif rule_conf > 0:
        combined_confidence = rule_conf
    elif semantic_conf > 0:
        combined_confidence = semantic_conf

    # 威胁等级
    if combined_confidence >= 70:
        threat_level = "high"
    elif combined_confidence >= 40:
        threat_level = "medium"
    elif combined_confidence >= 15:
        threat_level = "low"
    else:
        threat_level = "none"

    elapsed_ms = round((time.time() - start) * 1000, 1)

    return overall, " | ".join(reasons) if reasons else "未检测到威胁", {
        "rule": {
            "alert":       rule_alert,
            "confidence":  rule_conf,
            "hit":         rule_hit,
            "all_hits":    [h.get("pattern", h.get("description", h.get("id", ""))) for h in rule_hits] if rule_hits else [],
            "categories":   list(set(h.get("category", "") for h in rule_hits)),
        },
        "semantic": {
            "alert":      semantic_alert,
            "confidence": semantic_conf,
        },
        "combined":         combined_confidence,
        "api_fallback":    api_fallback,
        "threat_level":    threat_level,
        "detection_time_ms": elapsed_ms,
    }


def get_detection_insight(result: dict, text: str = "") -> str:
    """
    根据检测结果生成 AI 置信度文字解读。
    """
    combined = result.get("combined", 0)
    threat   = result.get("threat_level", "none")
    rule     = result.get("rule", {})
    sem      = result.get("semantic", {})
    fallback = result.get("api_fallback", False)

    parts = []
    if threat == "high":
        parts.append(f"高危威胁（置信度 {combined}%）")
    elif threat == "medium":
        parts.append(f"中危威胁（置信度 {combined}%）")
    elif threat == "low":
        parts.append(f"低危告警（置信度 {combined}%）")
    else:
        parts.append(f"未检测到明确威胁（置信度 {combined}%）")

    if rule.get("alert"):
        cats = ", ".join(rule.get("categories", []))
        parts.append(f"规则引擎命中{cats}类攻击模式")

    if sem.get("alert"):
        parts.append("语义分析判定为恶意")

    if fallback:
        parts.append("（语义API降级至本地引擎）")

    return "；".join(parts)
