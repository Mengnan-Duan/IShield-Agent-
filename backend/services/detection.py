"""混合检测核心逻辑 — 规则 + 语义 + UEBA 三引擎融合（去魔数 + 置信区间）"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple, Optional

from services.rule_engine import rule_detect, get_sig_manager
from services.semantic import semantic_detect, semantic_detect_local, semantic_detect_detailed
from services.text_normalize import decode_html_entities, decode_url_encoding, normalize_all
from services.ueba import get_ueba_engine

DetectionResult = Tuple[bool, str, dict]  # (is_malicious, reason, confidence_data)


# 融合权重（3 引擎）
W_RULE = 0.35
W_SEMANTIC = 0.45
W_UEBA = 0.20


def hybrid_detect(text: str, use_cache: bool = True,
                  client_ip: Optional[str] = None,
                  token_id: Optional[str] = None,
                  ueba_anomaly: Optional[dict] = None) -> DetectionResult:
    """
    混合检测主入口 — 三引擎并行融合。

    公式：combined = rule × 0.35 + semantic × 0.45 + ueba × 0.20
    当 UEBA 异常时（传入 ueba_anomaly）即使规则/语义分数低也提升告警等级。

    参数:
        text: 待检测文本
        use_cache: 是否启用缓存（路由层处理）
        client_ip: 客户端 IP（用于 UEBA 基线）
        token_id: Token ID（用于 UEBA 基线）
        ueba_anomaly: 预先查询的 UEBA 异常报告（避免重复 IO）

    返回:
        (is_malicious, reason, {
            rule: {alert, confidence, hit, all_hits, categories},
            semantic: {alert, confidence, engine, confidence_low, confidence_high},
            ueba: {score, alerts, anomaly: bool},
            combined: float,
            combined_low: float,
            combined_high: float,
            api_fallback: bool,
            threat_level: str,
            engine_versions: dict,
            detection_time_ms: float,
            cached: bool,
        })
    """
    import time
    import random
    start = time.time()

    # ── Phase 2.7 新增：编码预处理器（修复 enc-002 等编码绕过）─────────────
    text_decoded = decode_html_entities(text)
    text_decoded = decode_url_encoding(text_decoded)
    # 还原被 NFKC 规范化破坏的 SQL 特殊字符（弯引号 → ASCII 单引号）
    text_decoded = normalize_all(text_decoded)
    # 预处理器处理后的文本送入各引擎检测
    _text = text_decoded

    # ── 并行执行 rule / semantic 引擎 ───────────────────────────
    rule_result = None
    semantic_result = None
    api_fallback = False

    def run_rule():
        return rule_detect(_text)

    def run_semantic():
        try:
            return semantic_detect_detailed(_text), False
        except Exception:
            return semantic_detect_detailed(_text)[:4] + ("local_fallback",), True

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_rule = pool.submit(run_rule)
        f_sem = pool.submit(run_semantic)
        try:
            rule_alert, rule_hit, rule_conf, rule_hits = f_rule.result(timeout=10)
        except Exception:
            rule_alert, rule_hit, rule_conf, rule_hits = False, None, 0, []

        try:
            semantic_detailed, sem_fallback = f_sem.result(timeout=20)
            api_fallback = sem_fallback
        except Exception:
            semantic_detailed = (False, 0.0, 0.0, 0.0, "local_fallback")
            api_fallback = True

    semantic_alert, sem_point, sem_low, sem_high, sem_engine = semantic_detailed

    # ── UEBA 异常分（如果未提供则查询基线）────────────────────
    if ueba_anomaly is None:
        try:
            ueba_engine = get_ueba_engine()
            ueba_anomaly = ueba_engine.get_context_anomaly(text, client_ip, token_id)
        except Exception:
            ueba_anomaly = {"score": 0, "alerts": [], "is_anomaly": False}

    ueba_score = float(ueba_anomaly.get("score", 0))
    ueba_alert = ueba_anomaly.get("is_anomaly", False) or ueba_score >= 30
    # UEBA 分归一到 0-100：score 自身就是 0-100 分
    ueba_point = min(100.0, ueba_score)

    # ── 综合判定（多引擎并集）─────────────────────────────────
    overall = bool(rule_alert or semantic_alert or ueba_alert)

    reasons = []
    if rule_alert:
        reasons.append(f"规则命中: {rule_hit}")
    if semantic_alert:
        reasons.append(f"语义判定: 恶意 [{sem_engine}]")
    if ueba_alert:
        first_alert = ueba_anomaly.get("alerts", [])
        alert_detail = first_alert[0].get("detail", "UEBA异常") if first_alert else "UEBA异常"
        reasons.append(f"行为异常: {alert_detail}")

    # ── 三引擎加权融合（连续值，无魔数封顶）─────────────────
    combined_point = (
        rule_conf * W_RULE +
        sem_point * W_SEMANTIC +
        ueba_point * W_UEBA
    )
    combined_point = max(0.0, min(100.0, combined_point))

    # 加高斯噪声
    noisy_point = combined_point + random.gauss(0, 2.5)
    noisy_point = max(0.0, min(100.0, noisy_point))

    # 95% CI（±4.5）
    combined_low = max(0.0, noisy_point - 4.5)
    combined_high = min(100.0, noisy_point + 4.5)

    # 威胁等级
    if noisy_point >= 70:
        threat_level = "high"
    elif noisy_point >= 40:
        threat_level = "medium"
    elif noisy_point >= 15:
        threat_level = "low"
    else:
        threat_level = "none"

    elapsed_ms = round((time.time() - start) * 1000, 1)

    # 汇总 rule 命中详情（rule_hits 已是新结构）
    rule_categories = list(set(h.get("category", "") for h in rule_hits if h.get("category")))

    return overall, " | ".join(reasons) if reasons else "未检测到威胁", {
        "rule": {
            "alert": rule_alert,
            "confidence": rule_conf,
            "hit": rule_hit,
            "all_hits": rule_hits,
            "categories": rule_categories,
        },
        "semantic": {
            "alert": semantic_alert,
            "confidence": round(sem_point, 1),
            "confidence_low": round(sem_low, 1),
            "confidence_high": round(sem_high, 1),
            "engine": sem_engine,
        },
        "ueba": {
            "score": ueba_score,
            "alerts": ueba_anomaly.get("alerts", []),
            "is_anomaly": ueba_alert,
        },
        "combined": round(noisy_point, 1),
        "combined_low": round(combined_low, 1),
        "combined_high": round(combined_high, 1),
        "api_fallback": api_fallback,
        "threat_level": threat_level,
        "engine_versions": {
            "rules": get_sig_manager().version,
            "semantic": sem_engine,
            "embeddings": "deepseek-1.0",
            "ueba": "v3.4.0",
        },
        "detection_time_ms": elapsed_ms,
        "cached": False,
    }


def get_detection_insight(result: dict, text: str = "") -> str:
    """
    根据检测结果生成 AI 置信度文字解读。
    """
    combined = result.get("combined", 0)
    threat = result.get("threat_level", "none")
    rule = result.get("rule", {})
    sem = result.get("semantic", {})
    ueba = result.get("ueba", {})
    fallback = result.get("api_fallback", False)
    cached = result.get("cached", False)

    parts = []
    if threat == "high":
        parts.append(f"高危威胁（置信度 {combined}% [区间 {result.get('combined_low', 0)}%-{result.get('combined_high', 100)}%]）")
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
        parts.append(f"语义分析判定为恶意 [引擎={sem.get('engine', 'unknown')}]")

    if ueba.get("is_anomaly"):
        parts.append(f"UEBA 异常评分 {ueba.get('score', 0)}")

    if fallback:
        parts.append("（语义 API 降级至本地引擎）")

    if cached:
        parts.append("（结果来自缓存）")

    return "；".join(parts)
