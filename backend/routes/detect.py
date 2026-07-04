"""检测路由 + 健康检查"""
import time
import hashlib
import uuid
from flask import Blueprint, request, jsonify, g

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response, make_error, Err
from utils.validators import validate_sanitize_text
from middleware.error_handler import ValidationError, BusinessError
from middleware.logger import get_logger

from services.detection import hybrid_detect, get_detection_insight
from services.rule_engine import get_sig_manager
from services.context_guard import check_context_integrity
from services.output_guard import scan_output, redact_output
from services.events import (
    add_event,
    get_cached_detection,
    set_cached_detection,
    cleanup_expired_cache,
)
from utils.cache import detect_cache
from services.samples import add_sample
from services.websocket import broadcast_detection, broadcast_alert
from utils.normalize import normalize_input, detect_homograph_attack
from utils.sanitize import sanitize_output
from middleware.auth import _get_client_ip

logger = get_logger()
detect_bp = Blueprint("detect", __name__, url_prefix="/api")


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:32]


@detect_bp.route("/detect", methods=["POST"])
def detect():
    # ── 1. 解析 & 校验 ──────────────────────────────────────────────
    if not request.is_json:
        raise ValidationError("请求 Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    raw_text = data.get("text", "")
    text, val_err = validate_sanitize_text(raw_text)
    if val_err:
        raise ValidationError(val_err)

    # ── 多轮上下文支持 ──────────────────────────────────────────────
    conversation_id = data.get("conversation_id") or data.get("chain_id")
    prior_turns = data.get("prior_turns") or []
    if conversation_id and not prior_turns:
        # 从 events 表按 chain_id 拉取前 N 轮
        try:
            from services.events import get_chain_events
            chain = get_chain_events(conversation_id)
            prior_turns = [
                {"role": "user", "content": e.get("detail", "")[:500]}
                for e in chain[-20:] if e.get("type", "").startswith("检测")
            ]
        except Exception:
            prior_turns = []
    client_ip_override = data.get("client_ip") or _get_client_ip()
    token_id_override = data.get("token_id")

    # ── Unicode归一化防御 ────────────────────────────────────────────
    normalized = normalize_input(text)
    homograph_warnings = detect_homograph_attack(text) if normalized != text else []

    # init 探测：只查状态，不记日志
    is_init_probe = (text == "init")

    # ── 缓存查询 ────────────────────────────────────────────────
    # 多轮上下文时，缓存 key 含 conversation_id，避免不同会话冲突
    cache_key_text = f"{conversation_id}:{normalized}" if conversation_id else normalized
    h = _text_hash(cache_key_text)
    cached = get_cached_detection(h) if not is_init_probe else None

    if cached:
        # 命中缓存，直接返回（节省 API 调用）
        conf_data = cached.get("confidence", {})
        g._threat_detected = conf_data.get("combined", 0) >= 15
        g._confidence      = conf_data.get("combined", 0)

        # init 探测只返回基本信息
        if is_init_probe:
            return make_response({
                "signature_count": get_sig_manager().version,
                "api_enabled":    _api_enabled(),
                "api_fallback":   False,
                "status":         "ok",
                "cached":         True,
            })

        return make_response({
            **cached,
            "cached": True,
            "insight": get_detection_insight(conf_data, text),
        })

    # ── 执行检测（多轮上下文 + UEBA 融合）──────────────────────
    start = time.time()
    is_malicious, reason, confidence_data = hybrid_detect(
        normalized,
        client_ip=client_ip_override,
        token_id=token_id_override,
    )
    elapsed_ms = int((time.time() - start) * 1000)

    # ── 多轮上下文累积风险评估 ────────────────────────────────────
    progressive_bonus = 0
    context_risk_curve = []
    if prior_turns:
        weights = [1.0 + 0.2 * i for i in range(len(prior_turns))]
        cumulative = 0.0
        for idx, turn in enumerate(prior_turns[-20:]):
            # 对每条历史 turn 也跑一次 hybrid_detect（轻量）
            try:
                _, _, hist_conf = hybrid_detect(
                    turn.get("content", ""),
                    client_ip=client_ip_override,
                    token_id=token_id_override,
                )
                risk = hist_conf.get("combined", 0)
            except Exception:
                risk = 0
            cumulative += risk * weights[idx]
            context_risk_curve.append(round(risk, 1))
        # 当前 turn 风险
        context_risk_curve.append(round(confidence_data.get("combined", 0), 1))
        # 渐进式诱导：累积风险超过阈值时按指数加权放大
        avg_prior = sum(context_risk_curve[:-1]) / max(len(context_risk_curve) - 1, 1)
        if avg_prior >= 20 and len(context_risk_curve) >= 3:
            # 累积趋势上升：加 0~25 分
            progressive_bonus = min(25, int(avg_prior * 0.5))
            confidence_data["combined"] = min(
                100,
                confidence_data.get("combined", 0) + progressive_bonus,
            )
            confidence_data["progressive_injection_score"] = progressive_bonus
            confidence_data["context_risk_curve"] = context_risk_curve
            if avg_prior >= 40:
                is_malicious = True
                reason += f" | 多轮上下文累积风险（平均 {avg_prior:.1f}）"

    # ── Phase 2.1 增强：上下文完整性检测 ───────────────────────
    # 将单轮输入包装为单条 turn，检测上下文注入意图
    single_turn = [{"role": "user", "content": normalized, "turn_index": 0}]
    ctx_check = check_context_integrity(single_turn)
    if ctx_check.get("violations"):
        ctx_score = ctx_check.get("score", 0)
        ctx_conf = min(int(ctx_score * 0.6), 30)
        # 上下文问题累积到综合置信度
        confidence_data["combined"] = confidence_data.get("combined", 0) + ctx_conf
        confidence_data["context_guard"] = {
            "status": ctx_check.get("integrity_status"),
            "score": ctx_score,
            "violations": len(ctx_check.get("violations", [])),
        }
        if ctx_score >= 40:
            is_malicious = True
            reason = (reason + " | 上下文异常: " +
                      "; ".join(v.get("type", "") for v in ctx_check.get("violations", [])))

    # ── Phase 2.1 增强：输出内容安全扫描 ────────────────────────
    # 在返回前扫描模型输出（如果未来模型直接返回内容）
    # 当前记录扫描结果，由上层决定是否阻断
    output_scan_result = scan_output(normalized)
    if output_scan_result[0]:
        findings = output_scan_result[1]
        # 敏感信息在输入中出现 = 可能的提取尝试
        secret_conf = max(f.get("confidence", 0) for f in findings) if findings else 0
        if secret_conf >= 60:
            confidence_data["combined"] = confidence_data.get("combined", 0) + min(secret_conf // 2, 25)
            confidence_data["output_guard"] = {
                "secrets_detected": len(findings),
                "max_confidence": secret_conf,
                "types": [f.get("type", "") for f in findings[:3]],
            }
            is_malicious = True
            reason = reason + " | 检测到敏感信息提取尝试"

    # 默认阈值
    DEFAULT_THRESHOLDS = {"low": 15, "medium": 40, "high": 70}

    def _dynamic_thresholds(ueba_anomaly: dict, recent_repeats: int = 0) -> dict:
        """根据 UEBA 异常和重复率动态调整威胁阈值。"""
        thresholds = dict(DEFAULT_THRESHOLDS)
        adjustments = []
        if ueba_anomaly and ueba_anomaly.get("is_anomaly"):
            thresholds["low"] = 10
            thresholds["medium"] = 30
            thresholds["high"] = 60
            adjustments.append("UEBA异常 → 阈值下调")
        if recent_repeats >= 5:
            thresholds["low"] = max(thresholds["low"], 20)
            thresholds["medium"] = max(thresholds["medium"], 50)
            thresholds["high"] = max(thresholds["high"], 80)
            adjustments.append(f"重复{recent_repeats}次 → 阈值上调")
        thresholds["adjustments"] = adjustments
        return thresholds

    def _count_recent_repeats(th: str) -> int:
        """统计同一 text_hash 在最近 5 分钟内的命中次数。"""
        try:
            from services.events import get_events_from_db
            rows = get_events_from_db(limit=50, type_filter="检测")
            return sum(1 for r in rows if r.get("text_hash") == th)
        except Exception:
            return 0

    # 重新计算威胁等级
    combined = confidence_data.get("combined", 0)

    # 动态阈值
    thresholds = _dynamic_thresholds(
        confidence_data.get("ueba"),
        recent_repeats=_count_recent_repeats(h),
    )
    if combined >= thresholds["high"]:
        confidence_data["threat_level"] = "high"
    elif combined >= thresholds["medium"]:
        confidence_data["threat_level"] = "medium"
    elif combined >= thresholds["low"]:
        confidence_data["threat_level"] = "low"
    else:
        confidence_data["threat_level"] = "none"
    confidence_data["dynamic_thresholds"] = thresholds

    g._threat_detected = is_malicious
    g._confidence      = confidence_data.get("combined", 0)

    status = "malicious" if is_malicious else "safe"

    result = {
        "status":           status,
        "reason":           reason if is_malicious else "",
        "signature_count":  len(get_sig_manager().rules),
        "api_provider":     _api_provider(),
        "api_enabled":      _api_enabled(),
        "api_fallback":     confidence_data.get("api_fallback", False),
        "confidence":       confidence_data,
        "elapsed_ms":       elapsed_ms,
        "insight":         get_detection_insight(confidence_data, normalized),
        "normalized":      normalized if normalized != text else None,
        "homograph_warnings": homograph_warnings,
        # Phase 2.1 增强字段
        "context_guard":    confidence_data.get("context_guard"),
        "output_guard":     confidence_data.get("output_guard"),
    }
    chain_id_for_event = None
    if not is_init_probe:
        chain_id_for_event = str(conversation_id or f"chain-detect-{uuid.uuid4().hex[:10]}").strip()
        result["chain_id"] = chain_id_for_event
        result["status_code"] = "blocked" if is_malicious else "allowed"
        result["runtime_conclusion"] = (
            f"输入检测已阻断：{reason}" if is_malicious else "输入检测已放行，审计证据已记录。"
        )

    # ── 4. 缓存写入 & 事件记录 ───────────────────────────────────
    if not is_init_probe:
        set_cached_detection(h, result, ttl_seconds=600)

        source_ip = _get_client_ip()
        # 多轮上下文支持：把 conversation_id 写入 chain_id，便于后续回溯
        chain_id_for_event = chain_id_for_event or conversation_id
        add_event(
            event_type="检测" if is_malicious else "放行",
            detail=f"输入: {text[:50]}... | {reason}" if is_malicious else f"输入: {text[:50]}...",
            status="已拦截" if is_malicious else "已放行",
            text_hash=h,
            threat_level=confidence_data.get("threat_level", "none"),
            confidence=confidence_data.get("combined", 0),
            source_ip=source_ip,
            chain_id=chain_id_for_event,
            metadata={
                "conversation_id": conversation_id,
                "decision": "blocked" if is_malicious else "allowed",
                "runtime_status": "blocked" if is_malicious else "allowed",
                "status_code": "blocked" if is_malicious else "allowed",
                "progressive_injection_score": confidence_data.get("progressive_injection_score"),
                "ueba_score": confidence_data.get("ueba", {}).get("score", 0),
            },
            stage="input_detection",
        )

        # 恶意样本自动归档
        if is_malicious:
            rule_hits = confidence_data.get("rule", {}).get("all_hits", [])
            rule_categories = list({r.get("category", "未知") for r in rule_hits})
            add_sample(
                text=text,
                reason=reason or "",
                category="; ".join(rule_categories) if rule_categories else confidence_data.get("threat_level", "未知"),
                threat_level=confidence_data.get("threat_level", "none"),
                confidence=confidence_data.get("combined", 0),
                rule_hits=rule_hits,
                semantic_hits={"alert": confidence_data.get("semantic", {}).get("alert", False)},
                source="detect",
            )

        # SSE 实时广播
        if not is_init_probe:
            broadcast_detection(
                text, is_malicious, reason,
                confidence_data.get("threat_level", "none"),
                confidence_data.get("combined", 0),
            )
            if is_malicious:
                broadcast_alert(
                    "检测", f"输入: {text[:50]}...",
                    "已拦截", confidence_data.get("threat_level", "none"),
                    confidence_data.get("combined", 0),
                )

    # init 探测只返回基本信息
    if is_init_probe:
        return make_response({
            "signature_count": len(get_sig_manager().rules),
            "api_enabled":    _api_enabled(),
            "api_fallback":   confidence_data.get("api_fallback", False),
            "status":         "ok",
        })

    return make_response(result, chain_id=result.get("chain_id"))


@detect_bp.route("/cache/clear", methods=["POST"])
def clear_cache():
    """清除检测缓存（签名更新后调用，避免旧结果干扰）"""
    detect_cache.clear()
    cleanup_expired_cache()
    return make_response({
        "message": "缓存已清除",
        "cache_cleared": True,
    })


@detect_bp.route("/health", methods=["GET"])
def health():
    """
    健康检查端点 — 前端 initBackend() 应改为调用此端点。
    返回各引擎状态，不产生日志记录。
    """
    # 清理过期缓存
    deleted = cleanup_expired_cache()

    api_enabled  = _api_enabled()
    sig_mgr      = get_sig_manager()

    # DB 健康检查
    db_healthy = True
    try:
        from services.events import get_events_from_db
        get_events_from_db(limit=1)
    except Exception:
        db_healthy = False

    healthy = db_healthy  # API key 缺失不算 unhealthy（本地引擎可正常工作）

    status = {
        "status":        "healthy" if healthy else "degraded",
        "db":            "connected" if db_healthy else "disconnected",
        "api_engine":    "enabled" if api_enabled else "local_only",
        "rule_count":    len(sig_mgr.rules),
        "semantic_patterns": len(sig_mgr.semantic_patterns),
        "cache_cleaned": deleted,
        "version":       sig_mgr.version,
        "timestamp":     __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
    }

    http_status = 200 if healthy else 503
    return jsonify({"success": True, "data": status}), http_status


# ── helpers ─────────────────────────────────────────────────────────────────
def _api_enabled():
    import config
    return bool(config.API_KEY and config.API_PROVIDER.lower() != "local")


def _api_provider():
    import config
    return config.API_PROVIDER.lower()
