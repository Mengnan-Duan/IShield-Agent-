"""模拟路由 — 沙箱执行 + 策略引擎双重检查"""
from flask import Blueprint, request

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

    # ── 第1层：上下文注入检测 ───────────────────────────────
    context = f"执行工具：{action}，参数：{params}"
    is_malicious, reason, _ = hybrid_detect(context)

    if is_malicious:
        add_event(
            event_type="沙箱拦截",
            detail=f"工具={action}, 参数={params[:50]}, 原因={reason}",
            status="已阻断",
        )
        broadcast_alert("沙箱拦截", f"工具={action}", "已阻断", "high", 80)
        return make_response({
            "result":  "blocked",
            "reason":  f"检测到注入攻击：{reason}",
            "context": "sandbox",
            "action":  action,
        })

    # ── 第2层：可配置策略引擎评估 ──────────────────────────
    engine = get_policy_engine()
    policy_result = engine.evaluate(action, params)

    if policy_result.action == Action.BLOCK:
        add_event(
            event_type="策略拦截",
            detail=f"工具={action}, 参数={params[:50]}, 策略={policy_result.triggered_rule}",
            status="已阻断",
        )
        broadcast_alert("策略拦截", f"工具={action}", "已阻断", "high", policy_result.severity)
        return make_response({
            "result":         "blocked",
            "reason":         policy_result.message,
            "context":        "policy",
            "triggered_rule": policy_result.triggered_rule,
            "severity":       policy_result.severity,
            "action":         action,
        })

    if policy_result.action == Action.CONFIRM:
        add_event(
            event_type="策略确认",
            detail=f"工具={action}, 参数={params[:50]}, 策略={policy_result.triggered_rule}",
            status="需确认",
        )
        return make_response({
            "result":         "confirm",
            "reason":         policy_result.message,
            "context":        "policy",
            "triggered_rule": policy_result.triggered_rule,
            "severity":       policy_result.severity,
            "action":         action,
        })

    # Action.ALLOW — 真实执行工具（沙箱内）
    tool_result = run_tool(action, params)
    tool_status = tool_result.get("status", "unknown")

    if tool_status == "executed":
        add_event(
            event_type="沙箱放行",
            detail=f"工具={action}, 参数={params[:50]}, 执行成功",
            status="已放行",
        )
        return make_response({
            "result":  "allowed",
            "message": f"工具 {action} 执行成功（{tool_result.get('_meta',{}).get('tool','')}沙箱）",
            "tool_result": tool_result,
            "action":  action,
            "sandbox_mode": "real" if tool_result.get("_meta",{}).get("status") == "executed" else "mock",
        })
    elif tool_status == "timeout":
        return make_response({
            "result": "timeout",
            "reason": f"工具 {action} 执行超时",
            "tool_result": tool_result,
            "action": action,
        })
    else:
        add_event(
            event_type="工具错误",
            detail=f"工具={action}, 错误={tool_status}",
            status="已出错",
        )
        return make_response({
            "result":  "error",
            "reason":  f"工具执行失败: {tool_status}",
            "tool_result": tool_result,
            "action":  action,
        })
