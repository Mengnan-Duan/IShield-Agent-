"""安全策略管理路由 — 查询/更新/评估安全策略"""
from flask import Blueprint, request, jsonify, current_app
import json, os

import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from middleware.error_handler import ValidationError, BusinessError
from middleware.logger import get_logger
from utils.response import make_response, make_error, Err

from services.policy import get_policy_engine, Action

logger = get_logger()
policy_bp = Blueprint("policy", __name__, url_prefix="/api/policies")


# ── 查询 ───────────────────────────────────────────────────────────────────────
@policy_bp.route("", methods=["GET"])
def list_policies():
    """
    GET /api/policies
    返回当前所有启用的策略规则列表。
    """
    engine = get_policy_engine()
    rules = [
        {
            "id": r.id,
            "name": r.name,
            "tool": r.tool,
            "params_pattern": r.params_pattern,
            "threat_keywords": r.threat_keywords,
            "action": r.action.value,
            "severity": r.severity,
            "message": r.message,
            "enabled": r.enabled,
        }
        for r in engine.rules
    ]
    return make_response({"rules": rules, "total": len(rules)})


# ── 评估 ───────────────────────────────────────────────────────────────────────
@policy_bp.route("/evaluate", methods=["POST"])
def evaluate_call():
    """
    POST /api/policies/evaluate
    评估单个或多个工具调用。
    body: {"tool": "...", "params": "..."}  或
          {"calls": [{"tool": "...", "params": "..."}, ...]}
    返回: action (allow / block / confirm), severity, message
    """
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    engine = get_policy_engine()

    # 批量模式
    calls = data.get("calls", [])
    if calls:
        results = engine.evaluate_batch(calls)
        return make_response({
            "results": [
                {
                    "tool": c["tool"],
                    "params_preview": c.get("params", "")[:100],
                    "action": r.action.value,
                    "triggered_rule": r.triggered_rule,
                    "message": r.message,
                    "severity": r.severity,
                    "matched_keywords": r.matched_keywords,
                }
                for c, r in zip(calls, results)
            ]
        })

    # 单条模式
    tool = data.get("tool", "").strip()
    params = data.get("params", "")
    if not tool:
        raise ValidationError("tool 参数不能为空")

    result = engine.evaluate(tool, params)
    return make_response({
        "tool": tool,
        "params_preview": params[:100],
        "action": result.action.value,
        "triggered_rule": result.triggered_rule,
        "message": result.message,
        "severity": result.severity,
        "matched_keywords": result.matched_keywords,
    })


# ── 热重载 ─────────────────────────────────────────────────────────────────────
@policy_bp.route("/reload", methods=["POST"])
def reload_policies():
    """
    POST /api/policies/reload
    热重载策略文件，无需重启服务。
    """
    engine = get_policy_engine()
    engine.reload()
    return make_response({
        "reloaded": True,
        "rule_count": len(engine.rules),
    })


# ── 导出/导入 ─────────────────────────────────────────────────────────────────
@policy_bp.route("/export", methods=["GET"])
def export_policy():
    """
    GET /api/policies/export
    导出当前策略配置为 JSON。
    """
    engine = get_policy_engine()
    rules = [
        {
            "id": r.id,
            "name": r.name,
            "tool": r.tool,
            "params_pattern": r.params_pattern,
            "threat_keywords": r.threat_keywords,
            "action": r.action.value,
            "severity": r.severity,
            "message": r.message,
            "enabled": r.enabled,
        }
        for r in engine.rules
    ]
    return jsonify({
        "success": True,
        "data": {
            "rules": rules,
            "exported_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ).isoformat(),
        }
    })


@policy_bp.route("/import", methods=["POST"])
def import_policy():
    """
    POST /api/policies/import
    导入新策略配置（覆盖写入 policies/default_policy.json）。
    """
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    rules = data.get("rules", [])
    if not rules:
        raise ValidationError("rules 不能为空")

    policy_dir = os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
        "policies"
    )
    os.makedirs(policy_dir, exist_ok=True)
    policy_file = os.path.join(policy_dir, "default_policy.json")

    with open(policy_file, "w", encoding="utf-8") as f:
        json.dump({"rules": rules, "version": "1.0"}, f, ensure_ascii=False, indent=2)

    # 热重载
    engine = get_policy_engine()
    engine.reload()

    return make_response({
        "imported": True,
        "rule_count": len(engine.rules),
    })
