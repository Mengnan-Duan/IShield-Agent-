"""安全策略管理路由 — 查询/更新/评估安全策略"""
from flask import Blueprint, request, jsonify
import json, os

import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.policy import get_policy_engine

policy_bp = Blueprint("policy", __name__, url_prefix="/api/policies")


def _serialize_rule(rule):
    return {
        "id": rule.id,
        "name": rule.name,
        "tool": rule.tool,
        "params_pattern": rule.params_pattern,
        "threat_keywords": rule.threat_keywords,
        "action": rule.action.value,
        "severity": rule.severity,
        "message": rule.message,
        "enabled": rule.enabled,
    }


@policy_bp.route("", methods=["GET"])
def list_policies():
    engine = get_policy_engine()
    rules = [_serialize_rule(r) for r in engine.all_rules]
    return make_response({"rules": rules, "total": len(rules)})


@policy_bp.route("/evaluate", methods=["POST"])
def evaluate_call():
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    engine = get_policy_engine()
    include_disabled = bool(data.get("include_disabled", False))

    calls = data.get("calls", [])
    if calls:
        results = engine.evaluate_batch(calls, include_disabled=include_disabled)
        return make_response({
            "results": [
                {
                    "tool": c.get("tool", ""),
                    "params_preview": str(c.get("params", ""))[:100],
                    "action": r.action.value,
                    "triggered_rule": r.triggered_rule,
                    "message": r.message,
                    "severity": r.severity,
                    "matched_keywords": r.matched_keywords,
                }
                for c, r in zip(calls, results)
            ]
        })

    tool = str(data.get("tool", "")).strip()
    params = str(data.get("params", ""))
    if not tool:
        raise ValidationError("tool 参数不能为空")

    result = engine.evaluate(tool, params, include_disabled=include_disabled)
    return make_response({
        "tool": tool,
        "params_preview": params[:100],
        "action": result.action.value,
        "triggered_rule": result.triggered_rule,
        "message": result.message,
        "severity": result.severity,
        "matched_keywords": result.matched_keywords,
    })


@policy_bp.route("/reload", methods=["POST"])
def reload_policies():
    engine = get_policy_engine()
    engine.reload()
    return make_response({
        "reloaded": True,
        "rule_count": len(engine.rules),
    })


@policy_bp.route("/toggle", methods=["POST"])
def toggle_policy_rule():
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    rule_id = str(data.get("rule_id", "")).strip()
    enabled = data.get("enabled", None)
    if not rule_id:
        raise ValidationError("rule_id 不能为空")
    if enabled is None:
        raise ValidationError("enabled 不能为空")

    engine = get_policy_engine()
    rule = engine.toggle_rule(rule_id, bool(enabled))
    if not rule:
        raise ValidationError(f"未找到策略规则: {rule_id}")

    return make_response({
        "updated": True,
        "rule": _serialize_rule(rule),
    })


@policy_bp.route("/export", methods=["GET"])
def export_policy():
    engine = get_policy_engine()
    rules = [_serialize_rule(r) for r in engine.all_rules]
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
        json.dump({"rules": rules, "version": "1.1"}, f, ensure_ascii=False, indent=2)

    engine = get_policy_engine()
    engine.reload()

    return make_response({
        "imported": True,
        "rule_count": len(engine.rules),
    })
