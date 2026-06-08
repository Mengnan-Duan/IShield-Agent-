"""模拟路由 — 沙箱执行 + 策略引擎双重检查"""
from flask import Blueprint, request, g
import uuid

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response
from middleware.error_handler import ValidationError

from services.detection import hybrid_detect
from services.events import add_event
from services.policy import get_policy_engine, Action
from services.websocket import broadcast_alert
from tools.tool_runner import run_tool

simulate_bp = Blueprint("simulate", __name__, url_prefix="/api")


def _request_source_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    simulated = request.headers.get("X-Demo-Source-IP", "").strip()
    if simulated:
        return simulated.split(",")[0].strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


def _build_target(action: str, params: str) -> str:
    if not params:
        return ""
    if action == "send_email":
        for key in ["to=", '"to":', "'to':"]:
            if key in params:
                return params.split(key, 1)[1].split("&", 1)[0].split(",", 1)[0].strip(' "\'')
    if action in {"read_file", "write_file"}:
        for key in ["path=", "file=", "filename=", '"path":', '"file":', '"filename":']:
            if key in params:
                return params.split(key, 1)[1].split("&", 1)[0].split(",", 1)[0].strip(' "\'')
    if action == "http_request":
        for key in ["url=", "endpoint=", '"url":', '"endpoint":']:
            if key in params:
                return params.split(key, 1)[1].split("&", 1)[0].split(",", 1)[0].strip(' "\'')
    return params[:120]


@simulate_bp.route("/simulate", methods=["POST"])
def simulate():
    if not request.is_json:
        raise ValidationError("请求 Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    action = str(data.get("action", "")).strip()
    params = str(data.get("params", ""))

    if not action:
        raise ValidationError("action 参数不能为空")

    source_ip = _request_source_ip()
    target = _build_target(action, params)
    chain_id = data.get("chain_id") or f"chain-{uuid.uuid4().hex[:12]}"
    context = f"执行工具：{action}，参数：{params}"
    is_malicious, reason, confidence = hybrid_detect(context)
    confidence_score = confidence.get("combined", 0) if isinstance(confidence, dict) else 0
    threat_level = confidence.get("threat_level", "high") if isinstance(confidence, dict) else "high"

    add_event(
        event_type="攻击链开始",
        detail=f"工具={action}, 目标={target or '-'}",
        status="分析中",
        source_ip=source_ip,
        action=action,
        tool_name=action,
        target=target,
        category="attack_chain",
        threat_level=threat_level if is_malicious else "low",
        confidence=confidence_score,
        chain_id=chain_id,
        stage="request_received",
        metadata={"params": params[:300], "action": action},
    )

    if is_malicious:
        add_event(
            event_type="沙箱拦截",
            detail=f"工具={action}, 参数={params[:50]}, 原因={reason}",
            status="已阻断",
            source_ip=source_ip,
            action=action,
            tool_name=action,
            target=target,
            category="prompt_injection",
            threat_level=threat_level,
            confidence=confidence_score,
            metadata={"stage": "detection", "reason": reason, "params": params[:200]},
            chain_id=chain_id,
            stage="detection_blocked",
        )
        broadcast_alert(
            "沙箱拦截", f"工具={action}", "已阻断", threat_level, confidence_score,
            source_ip=source_ip, action=action, tool_name=action, target=target,
            category="prompt_injection", metadata={"reason": reason, "chain_id": chain_id},
        )
        return make_response({
            "result": "blocked",
            "reason": f"检测到注入攻击：{reason}",
            "context": "sandbox",
            "action": action,
            "source_ip": source_ip,
            "target": target,
            "chain_id": chain_id,
        })

    engine = get_policy_engine()
    policy_result = engine.evaluate(action, params)

    add_event(
        event_type="策略评估",
        detail=f"工具={action}, 动作={policy_result.action.value}, 规则={policy_result.triggered_rule or '-'}",
        status="已评估",
        source_ip=source_ip,
        action=action,
        tool_name=action,
        target=target,
        rule_id=policy_result.triggered_rule,
        category="policy_evaluation",
        threat_level="medium" if policy_result.action == Action.CONFIRM else "low",
        confidence=policy_result.severity,
        metadata={
            "message": policy_result.message,
            "matched_keywords": policy_result.matched_keywords,
            "decision": policy_result.action.value,
        },
        chain_id=chain_id,
        stage="policy_evaluated",
    )

    if policy_result.action == Action.BLOCK:
        add_event(
            event_type="策略拦截",
            detail=f"工具={action}, 参数={params[:50]}, 策略={policy_result.triggered_rule}",
            status="已阻断",
            source_ip=source_ip,
            action=action,
            tool_name=action,
            target=target,
            rule_id=policy_result.triggered_rule,
            category="policy_violation",
            threat_level="high",
            confidence=policy_result.severity,
            metadata={"stage": "policy", "message": policy_result.message},
            chain_id=chain_id,
            stage="policy_blocked",
        )
        broadcast_alert(
            "策略拦截", f"工具={action}", "已阻断", "high", policy_result.severity,
            source_ip=source_ip, action=action, tool_name=action, target=target,
            rule_id=policy_result.triggered_rule, category="policy_violation",
            metadata={"message": policy_result.message, "chain_id": chain_id},
        )
        return make_response({
            "result": "blocked",
            "reason": policy_result.message,
            "context": "policy",
            "triggered_rule": policy_result.triggered_rule,
            "severity": policy_result.severity,
            "action": action,
            "source_ip": source_ip,
            "target": target,
            "chain_id": chain_id,
        })

    if policy_result.action == Action.CONFIRM:
        add_event(
            event_type="策略确认",
            detail=f"工具={action}, 参数={params[:50]}, 策略={policy_result.triggered_rule}",
            status="需确认",
            source_ip=source_ip,
            action=action,
            tool_name=action,
            target=target,
            rule_id=policy_result.triggered_rule,
            category="policy_confirmation",
            threat_level="medium",
            confidence=policy_result.severity,
            metadata={"stage": "policy", "message": policy_result.message},
            chain_id=chain_id,
            stage="policy_confirm",
        )
        return make_response({
            "result": "confirm",
            "reason": policy_result.message,
            "context": "policy",
            "triggered_rule": policy_result.triggered_rule,
            "severity": policy_result.severity,
            "action": action,
            "source_ip": source_ip,
            "target": target,
            "chain_id": chain_id,
        })

    tool_result = run_tool(action, params, source_ip=source_ip, action=action, chain_id=chain_id, token_meta=getattr(g, 'token_meta', None))
    tool_status = tool_result.get("status", "unknown")

    if tool_status in {"executed", "mock"}:
        return make_response({
            "result": "allowed",
            "message": tool_result.get("summary", f"工具 {action} 执行成功"),
            "tool_result": tool_result,
            "action": action,
            "source_ip": source_ip,
            "target": target,
            "sandbox_mode": tool_result.get("mode", "mock"),
            "chain_id": chain_id,
        })
    if tool_status == "timeout":
        return make_response({
            "result": "timeout",
            "reason": f"工具 {action} 执行超时",
            "tool_result": tool_result,
            "action": action,
            "source_ip": source_ip,
            "target": target,
            "chain_id": chain_id,
        })

    return make_response({
        "result": "error",
        "reason": f"工具执行失败: {tool_result.get('summary', tool_status)}",
        "tool_result": tool_result,
        "action": action,
        "source_ip": source_ip,
        "target": target,
        "chain_id": chain_id,
    })
