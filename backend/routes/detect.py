"""检测路由 + 健康检查"""
import time
import hashlib
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

    # ── Unicode归一化防御 ────────────────────────────────────────────
    normalized = normalize_input(text)
    homograph_warnings = detect_homograph_attack(text) if normalized != text else []

    # init 探测：只查状态，不记日志
    is_init_probe = (text == "init")

    # ── 缓存查询 ────────────────────────────────────────────────
    h = _text_hash(normalized)
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

    # ── 执行检测 ────────────────────────────────────────────────
    start = time.time()
    is_malicious, reason, confidence_data = hybrid_detect(normalized)
    elapsed_ms = int((time.time() - start) * 1000)

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

    # 重新计算威胁等级
    combined = confidence_data.get("combined", 0)
    if combined >= 70:
        confidence_data["threat_level"] = "high"
    elif combined >= 40:
        confidence_data["threat_level"] = "medium"
    elif combined >= 15:
        confidence_data["threat_level"] = "low"
    else:
        confidence_data["threat_level"] = "none"

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

    # ── 4. 缓存写入 & 事件记录 ───────────────────────────────────
    if not is_init_probe:
        set_cached_detection(h, result, ttl_seconds=600)

        source_ip = _get_client_ip()
        add_event(
            event_type="检测" if is_malicious else "放行",
            detail=f"输入: {text[:50]}... | {reason}" if is_malicious else f"输入: {text[:50]}...",
            status="已拦截" if is_malicious else "已放行",
            text_hash=h,
            threat_level=confidence_data.get("threat_level", "none"),
            confidence=confidence_data.get("combined", 0),
            source_ip=source_ip,
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

    return make_response(result)


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
