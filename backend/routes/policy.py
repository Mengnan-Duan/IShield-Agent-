"""安全策略管理路由 — 查询/更新/评估安全策略"""
from flask import Blueprint, request, jsonify
import json

import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.policy import get_policy_engine, serialize_policy_result
from services.events import get_rule_hit_events, get_rule_hit_summary
from runtime_paths import backend_policies_dir

policy_bp = Blueprint("policy", __name__, url_prefix="/api/policies")


def _serialize_rule(rule):
    data = {
        "id": rule.id,
        "name": rule.name,
        "tool": rule.tool,
        "params_pattern": rule.params_pattern,
        "threat_keywords": rule.threat_keywords,
        "action": rule.action.value,
        "severity": rule.severity,
        "message": rule.message,
        "enabled": rule.enabled,
        "scope": rule.scope,
        "priority": rule.priority,
        "tags": rule.tags,
        "description": rule.description,
        "category": getattr(rule, "category", "runtime"),
        "attack_surface": getattr(rule, "attack_surface", "运行时工具调用"),
        "recommended_response": getattr(rule, "recommended_response", ""),
        "false_positive_note": getattr(rule, "false_positive_note", ""),
        "test_cases": getattr(rule, "test_cases", []),
    }
    data["conditions"] = [
        {"field": "tool", "operator": "glob", "value": rule.tool},
        {"field": "params", "operator": "regex", "value": rule.params_pattern},
        {"field": "params", "operator": "contains_any", "value": rule.threat_keywords},
    ]
    data["effect"] = {
        "block": "deny_execution",
        "confirm": "require_approval",
        "allow": "allow_execution",
        "log": "audit_only",
    }.get(rule.action.value, "audit_only")
    return data


def _event_brief(event):
    return {
        "id": event.get("id"),
        "time": event.get("time"),
        "type": event.get("type"),
        "detail": event.get("detail"),
        "status_code": event.get("status_code"),
        "status_label": event.get("status_label"),
        "threat_level": event.get("threat_level"),
        "confidence": event.get("confidence"),
        "tool_name": event.get("tool_name"),
        "action": event.get("action"),
        "target": event.get("target"),
        "rule_id": event.get("rule_id"),
        "category": event.get("category"),
        "chain_id": event.get("chain_id"),
        "stage": event.get("stage"),
    }


def _first_tool(tool_pattern):
    first = str(tool_pattern or "*").split("|")[0].strip()
    return first or "*"


def _normalize_policy_call(item, index=0):
    if not isinstance(item, dict):
        raise ValidationError(f"calls[{index}] must be an object")
    tool = str(item.get("tool", "")).strip()
    if not tool:
        raise ValidationError(f"calls[{index}].tool cannot be empty")
    return {
        "tool": tool,
        "params": item.get("params", ""),
    }


def _attach_hit_stats(rule_data, hit_stats):
    hit = hit_stats.get(rule_data.get("id")) or {}
    rule_data["hit_count"] = int(hit.get("hit_count") or 0)
    rule_data["blocked_count"] = int(hit.get("blocked_count") or 0)
    rule_data["confirm_count"] = int(hit.get("confirm_count") or 0)
    rule_data["allowed_count"] = int(hit.get("allowed_count") or 0)
    rule_data["last_hit_at"] = hit.get("last_hit_at")
    rule_data["last_event_id"] = hit.get("last_event_id")
    rule_data["chain_ids"] = hit.get("chain_ids") or []
    rule_data["recent_hits"] = hit.get("recent_events") or []
    return rule_data


@policy_bp.route("", methods=["GET"])
def list_policies():
    engine = get_policy_engine()
    hit_stats = {item.get("rule_id"): item for item in get_rule_hit_summary(limit=3000, per_rule_limit=5)}
    rules = [_attach_hit_stats(_serialize_rule(r), hit_stats) for r in engine.all_rules]
    return make_response({"rules": rules, "total": len(rules), "summary": engine.summary()})


@policy_bp.route("/hits", methods=["GET"])
def policy_hits():
    limit = request.args.get("limit", 3000, type=int)
    per_rule = request.args.get("per_rule", 5, type=int)
    hits = get_rule_hit_summary(limit=limit, per_rule_limit=per_rule)
    return make_response({
        "hits": hits,
        "total": len(hits),
    })


@policy_bp.route("/<rule_id>/hits", methods=["GET"])
def policy_rule_hits(rule_id: str):
    limit = request.args.get("limit", 20, type=int)
    events = get_rule_hit_events(rule_id, limit=limit)
    chain_ids = []
    for event in events:
        cid = event.get("chain_id")
        if cid and cid not in chain_ids:
            chain_ids.append(cid)
    return make_response({
        "rule_id": rule_id,
        "hit_count": len(events),
        "chain_count": len(chain_ids),
        "chain_ids": chain_ids,
        "last_hit_at": events[0].get("time") if events else None,
        "events": [_event_brief(event) for event in events],
    })


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
    if calls is None:
        calls = []
    if calls and not isinstance(calls, list):
        raise ValidationError("calls must be a list")
    if calls:
        normalized_calls = [_normalize_policy_call(call, idx) for idx, call in enumerate(calls)]
        results = engine.evaluate_batch(normalized_calls, include_disabled=include_disabled)
        return make_response({
            "results": [
                {
                    "tool": c.get("tool", ""),
                    "params_preview": str(c.get("params", ""))[:100],
                    **serialize_policy_result(r),
                }
                for c, r in zip(normalized_calls, results)
            ]
        })

    tool = str(data.get("tool", "")).strip()
    params = str(data.get("params", ""))
    if not tool:
        raise ValidationError("tool 参数不能为空")

    result = engine.evaluate(tool, params, include_disabled=include_disabled)
    payload = {
        "tool": tool,
        "params_preview": params[:100],
        **serialize_policy_result(result),
    }
    return make_response(payload)


@policy_bp.route("/reload", methods=["POST"])
def reload_policies():
    engine = get_policy_engine()
    engine.reload()
    return make_response({
        "reloaded": True,
        "rule_count": len(engine.rules),
        "summary": engine.summary(),
    })


@policy_bp.route("/summary", methods=["GET"])
def policy_summary():
    engine = get_policy_engine()
    return make_response(engine.summary())


@policy_bp.route("/matrix-test", methods=["POST"])
def matrix_test():
    engine = get_policy_engine()
    data = request.get_json(silent=True) if request.is_json else {}
    include_disabled = bool((data or {}).get("include_disabled", False))
    rules = engine.all_rules if include_disabled else engine.rules
    results = []
    category_stats = {}
    action_stats = {}

    for rule in rules:
        raw_cases = getattr(rule, "test_cases", [])
        cases = raw_cases if isinstance(raw_cases, list) and raw_cases else [_default_case(rule)]
        case_results = []
        hit_count = 0
        for case in cases[:5]:
            if not isinstance(case, dict):
                case = {}
            tool = str(case.get("tool") or _first_tool(rule.tool)).strip()
            params = case.get("params", "")
            expected = str(case.get("expected_action") or rule.action.value)
            result = engine.evaluate(tool, params, include_disabled=include_disabled)
            payload = serialize_policy_result(result)
            passed = result.triggered_rule == rule.id and result.action.value == expected
            hit_count += 1 if passed else 0
            case_results.append({
                "name": case.get("name") or rule.name,
                "tool": tool,
                "params_preview": str(params)[:160],
                "expected_action": expected,
                "actual_action": result.action.value,
                "triggered_rule": result.triggered_rule,
                "passed": passed,
                "explanation": payload.get("explanation"),
            })

        category = getattr(rule, "category", "runtime")
        action = rule.action.value
        category_stats.setdefault(category, {"total": 0, "passed": 0})
        category_stats[category]["total"] += len(case_results)
        category_stats[category]["passed"] += hit_count
        action_stats[action] = action_stats.get(action, 0) + 1
        results.append({
            "rule_id": rule.id,
            "rule_name": rule.name,
            "category": category,
            "attack_surface": getattr(rule, "attack_surface", "运行时工具调用"),
            "action": action,
            "severity": rule.severity,
            "case_count": len(case_results),
            "passed": hit_count,
            "coverage": round(hit_count / max(1, len(case_results)) * 100, 1),
            "cases": case_results,
        })

    total_cases = sum(item["case_count"] for item in results)
    passed_cases = sum(item["passed"] for item in results)
    return make_response({
        "version": "v4.9",
        "rule_count": len(results),
        "case_count": total_cases,
        "passed": passed_cases,
        "coverage": round(passed_cases / max(1, total_cases) * 100, 1),
        "category_stats": category_stats,
        "action_distribution": action_stats,
        "results": results,
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


def _default_case(rule):
    sample = " ".join((getattr(rule, "threat_keywords", []) or [])[:2]) or getattr(rule, "params_pattern", "") or "normal request"
    return {
        "name": f"{rule.id} 默认命中样本",
        "tool": _first_tool(rule.tool),
        "params": sample,
        "expected_action": rule.action.value,
    }


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

    policy_dir = backend_policies_dir()
    policy_file = policy_dir / "default_policy.json"

    with open(policy_file, "w", encoding="utf-8") as f:
        json.dump({"rules": rules, "version": "1.1"}, f, ensure_ascii=False, indent=2)

    engine = get_policy_engine()
    engine.reload()

    return make_response({
        "imported": True,
        "rule_count": len(engine.rules),
    })
