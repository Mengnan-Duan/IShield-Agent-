"""IShield v5.8 Attack Playbook Engine."""
from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from runtime_paths import bundled_path, runtime_data_dir
from services.events import add_event, get_chain_events
from services.runtime_gateway import execute_runtime_request


PLAYBOOK_VERSION = "v5.8"
PLAYBOOK_DIR = bundled_path("backend", "playbooks")
RESULT_STORE = runtime_data_dir() / "playbook_results.json"
_LAST_RESULTS: Dict[str, Any] = {}


def list_playbooks() -> Dict[str, Any]:
    playbooks = _load_playbooks()
    return {
        "version": PLAYBOOK_VERSION,
        "count": len(playbooks),
        "attack_surfaces": _surface_distribution(playbooks),
        "playbooks": [_public_playbook(item) for item in playbooks],
    }


def run_playbooks(payload: Dict[str, Any] = None, source_ip: str = None, trace_id: str = None, token_meta: dict = None) -> Dict[str, Any]:
    payload = payload or {}
    requested = payload.get("playbook_ids") or payload.get("ids")
    run_id = str(payload.get("run_id") or f"pbk-{uuid.uuid4().hex[:10]}").strip()
    agent_id = str(payload.get("agent_id") or "playbook-agent").strip()
    fast_detection = payload.get("fast_detection", True) is not False
    playbooks = _select_playbooks(_load_playbooks(), requested)
    started = time.perf_counter()

    add_event(
        event_type="攻击剧本运行启动",
        detail=f"run_id={run_id}, playbooks={len(playbooks)}",
        status="执行中",
        source_ip=source_ip or "127.0.0.1",
        action="playbook_run",
        tool_name="playbook_engine",
        target=run_id,
        category="attack_playbook",
        threat_level="low",
        confidence=0,
        chain_id=run_id,
        stage="playbook_run_started",
        metadata={"version": PLAYBOOK_VERSION, "run_id": run_id, "playbook_count": len(playbooks), "trace_id": trace_id},
    )

    results = [
        _run_single_playbook(
            playbook=playbook,
            run_id=run_id,
            agent_id=agent_id,
            source_ip=source_ip or "127.0.0.1",
            trace_id=trace_id,
            token_meta=token_meta,
            fast_detection=fast_detection,
            index=index,
        )
        for index, playbook in enumerate(playbooks, start=1)
    ]

    summary = _summary(results, started)
    output = {
        "version": PLAYBOOK_VERSION,
        "run_id": run_id,
        "status": "passed" if summary["failed"] == 0 else "review",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "surface_stats": _result_surface_stats(results),
        "results": results,
        "regression": _regression_summary(results),
        "next_action": _next_action(results),
    }

    add_event(
        event_type="攻击剧本运行结论",
        detail=f"剧本={summary['total']}, 通过={summary['passed']}, 异常={summary['failed']}, 阻断={summary['blocked_steps']}",
        status="已完成" if summary["failed"] == 0 else "需复核",
        source_ip=source_ip or "127.0.0.1",
        action="playbook_run",
        tool_name="playbook_engine",
        target=run_id,
        category="attack_playbook",
        threat_level="high" if summary["blocked_steps"] else "low",
        confidence=summary["highest_risk_score"],
        chain_id=run_id,
        stage="playbook_run_conclusion",
        metadata={"version": PLAYBOOK_VERSION, "run_id": run_id, "summary": summary},
    )

    _remember_result(output)
    return output


def latest_result(playbook_or_run_id: str = None) -> Dict[str, Any]:
    store = _load_result_store()
    runs = store.get("runs") or []
    if not runs:
        return {"version": PLAYBOOK_VERSION, "status": "empty", "summary": None, "results": []}
    if not playbook_or_run_id:
        return runs[0]
    key = str(playbook_or_run_id or "").strip()
    for run in runs:
        if run.get("run_id") == key:
            return run
        for result in run.get("results") or []:
            if result.get("playbook_id") == key:
                return {
                    "version": PLAYBOOK_VERSION,
                    "status": "found",
                    "run_id": run.get("run_id"),
                    "summary": run.get("summary"),
                    "result": result,
                }
    return {"version": PLAYBOOK_VERSION, "status": "not_found", "id": key, "summary": None, "results": []}


def regression_overview() -> Dict[str, Any]:
    latest = latest_result()
    if latest.get("status") == "empty":
        return {
            "version": PLAYBOOK_VERSION,
            "status": "empty",
            "summary": {"total": 0, "passed": 0, "failed": 0, "coverage": 0},
            "results": [],
        }
    results = latest.get("results") or []
    return {
        "version": PLAYBOOK_VERSION,
        "status": latest.get("status"),
        "run_id": latest.get("run_id"),
        "generated_at": latest.get("generated_at"),
        "summary": latest.get("summary"),
        "regression": latest.get("regression") or _regression_summary(results),
        "results": [
            {
                "playbook_id": item.get("playbook_id"),
                "title": item.get("title"),
                "attack_surface": item.get("attack_surface"),
                "passed": item.get("passed"),
                "decision": item.get("decision"),
                "blocked_at": item.get("blocked_at"),
                "matched_rules": item.get("matched_rules") or [],
                "chain_id": item.get("chain_id"),
                "assertions": item.get("assertions"),
            }
            for item in results
        ],
    }


def _run_single_playbook(
    playbook: Dict[str, Any],
    run_id: str,
    agent_id: str,
    source_ip: str,
    trace_id: str,
    token_meta: dict,
    fast_detection: bool,
    index: int,
) -> Dict[str, Any]:
    started = time.perf_counter()
    playbook_id = playbook["id"]
    chain_id = f"{run_id}-{playbook_id}"
    steps = []
    matched_rules = []
    decisions = []
    blocked_at_values = []
    risk_scores = []

    add_event(
        event_type="攻击剧本启动",
        detail=f"{playbook.get('title')} ({playbook_id})",
        status="执行中",
        source_ip=source_ip,
        action="playbook",
        tool_name="playbook_engine",
        target=playbook_id,
        category="attack_playbook",
        threat_level=_threat_from_severity(playbook.get("severity")),
        confidence=_severity_floor(playbook.get("severity")),
        chain_id=chain_id,
        stage="playbook_started",
        metadata={"run_id": run_id, "playbook": _public_playbook(playbook), "playbook_index": index, "trace_id": trace_id},
    )

    for step_index, step in enumerate(playbook.get("steps") or [], start=1):
        runtime = execute_runtime_request(
            action=step.get("action") or "agent_message",
            params=step.get("params") or {},
            chain_id=chain_id,
            source_ip=source_ip,
            token_meta=token_meta,
            trace_id=f"{trace_id or run_id}-{index}-{step_index}",
            actor=agent_id,
            fast_detection=fast_detection,
            user_input=step.get("input") or "",
        )
        decision = _normalize_decision(runtime.get("decision") or runtime.get("result"))
        blocked_at = _normalize_blocked_at(runtime.get("blocked_at"), decision)
        rule_id = runtime.get("triggered_rule") or runtime.get("rule_id") or _rule_from_steps(runtime.get("steps") or [])
        step_result = {
            "step_id": step.get("id") or f"step-{step_index}",
            "index": step_index,
            "title": step.get("title") or f"Step {step_index}",
            "action": step.get("action") or "agent_message",
            "decision": decision,
            "blocked_at": blocked_at,
            "rule_id": rule_id,
            "risk_score": int(runtime.get("risk_score") or 0),
            "reason": runtime.get("reason") or runtime.get("message") or "",
            "target": runtime.get("target"),
            "runtime_steps": runtime.get("steps") or [],
            "chain_id": runtime.get("chain_id") or chain_id,
        }
        steps.append(step_result)
        decisions.append(decision)
        blocked_at_values.append(blocked_at)
        risk_scores.append(step_result["risk_score"])
        if rule_id and rule_id not in matched_rules:
            matched_rules.append(rule_id)

    events = get_chain_events(chain_id)
    assertions = _evaluate_assertions(playbook, steps, matched_rules, events)
    passed = bool(assertions.get("passed"))
    final_decision = _final_decision(decisions)
    final_blocked_at = _final_blocked_at(blocked_at_values, final_decision)
    risk_score = max(risk_scores + [_severity_floor(playbook.get("severity"))], default=0)
    recommendation = _recommendation(playbook, passed, final_decision, final_blocked_at)

    result = {
        "version": PLAYBOOK_VERSION,
        "run_id": run_id,
        "playbook_id": playbook_id,
        "title": playbook.get("title"),
        "attack_surface": playbook.get("attack_surface"),
        "severity": playbook.get("severity"),
        "chain_id": chain_id,
        "decision": final_decision,
        "blocked_at": final_blocked_at,
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "passed": passed,
        "assertions": assertions,
        "matched_rules": matched_rules,
        "expected_rules": playbook.get("expected_rules") or [],
        "expected_blocked_stages": playbook.get("expected_blocked_stages") or [],
        "evidence_checkpoints": playbook.get("evidence_checkpoints") or [],
        "preconditions": playbook.get("preconditions") or [],
        "steps": steps,
        "evidence_items": _evidence_items(events, steps, playbook),
        "event_count": len(events),
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "recommendation": recommendation,
    }

    add_event(
        event_type="攻击剧本结论",
        detail=f"{playbook.get('title')}: {final_decision}, blocked_at={final_blocked_at}, regression={'pass' if passed else 'review'}",
        status="已完成" if passed else "需复核",
        source_ip=source_ip,
        action="playbook",
        tool_name="playbook_engine",
        target=playbook_id,
        rule_id=matched_rules[0] if matched_rules else None,
        category="attack_playbook",
        threat_level=result["risk_level"],
        confidence=risk_score,
        chain_id=chain_id,
        stage="playbook_conclusion",
        metadata={"run_id": run_id, "playbook_result": result},
    )
    result["event_count"] = len(get_chain_events(chain_id))
    return result


def _load_playbooks() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not PLAYBOOK_DIR.exists():
        return rows
    for path in sorted(PLAYBOOK_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = payload.get("playbooks") if isinstance(payload, dict) else payload
        if isinstance(items, list):
            rows.extend(item for item in items if isinstance(item, dict) and item.get("id"))
    rows.sort(key=lambda item: str(item.get("id") or ""))
    return rows


def _select_playbooks(playbooks: List[Dict[str, Any]], requested: Any) -> List[Dict[str, Any]]:
    if not requested:
        return playbooks
    ids = {str(item).strip() for item in requested if str(item).strip()} if isinstance(requested, list) else {str(requested).strip()}
    selected = [item for item in playbooks if item.get("id") in ids]
    return selected or playbooks


def _public_playbook(item: Dict[str, Any]) -> Dict[str, Any]:
    steps = item.get("steps") or []
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "attack_surface": item.get("attack_surface"),
        "severity": item.get("severity"),
        "step_count": len(steps),
        "preconditions": item.get("preconditions") or [],
        "expected_rules": item.get("expected_rules") or [],
        "expected_blocked_stages": item.get("expected_blocked_stages") or [],
        "evidence_checkpoints": item.get("evidence_checkpoints") or [],
        "regression_assertions": item.get("regression_assertions") or {},
        "steps": [
            {
                "id": step.get("id"),
                "title": step.get("title"),
                "action": step.get("action"),
            }
            for step in steps
        ],
    }


def _summary(results: List[Dict[str, Any]], started: float) -> Dict[str, Any]:
    total = len(results)
    passed = sum(1 for item in results if item.get("passed"))
    failed = total - passed
    blocked_steps = sum(1 for item in results for step in item.get("steps") or [] if step.get("decision") == "blocked")
    allowed_steps = sum(1 for item in results for step in item.get("steps") or [] if step.get("decision") == "allowed")
    total_steps = sum(len(item.get("steps") or []) for item in results)
    highest = max((int(item.get("risk_score") or 0) for item in results), default=0)
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "coverage": round(passed / max(total, 1) * 100, 1),
        "total_steps": total_steps,
        "blocked_steps": blocked_steps,
        "allowed_steps": allowed_steps,
        "chain_count": total,
        "highest_risk_score": highest,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }


def _regression_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    passed = sum(1 for item in results if item.get("passed"))
    failed_items = [item for item in results if not item.get("passed")]
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "coverage": round(passed / max(total, 1) * 100, 1),
        "failed_playbooks": [item.get("playbook_id") for item in failed_items],
    }


def _evaluate_assertions(playbook: Dict[str, Any], steps: List[Dict[str, Any]], matched_rules: List[str], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    assertions = playbook.get("regression_assertions") or {}
    expected_decision = assertions.get("final_decision")
    expected_rules = set(playbook.get("expected_rules") or [])
    decisions = [step.get("decision") for step in steps]
    blocked = sum(1 for item in decisions if item == "blocked")
    allowed = sum(1 for item in decisions if item == "allowed")
    final_decision = _final_decision(decisions)
    checks = {
        "final_decision": (not expected_decision) or final_decision == expected_decision,
        "min_blocked_steps": blocked >= int(assertions.get("min_blocked_steps") or 0),
        "min_allowed_steps": allowed >= int(assertions.get("min_allowed_steps") or 0),
        "required_rules": (not assertions.get("require_rule_hit")) or bool(expected_rules.intersection(set(matched_rules))) or (not expected_rules and bool(matched_rules)),
        "chain_events": len(events) >= int(assertions.get("require_chain_events") or 0),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "final_decision": final_decision,
        "blocked_steps": blocked,
        "allowed_steps": allowed,
        "event_count": len(events),
    }


def _evidence_items(events: List[Dict[str, Any]], steps: List[Dict[str, Any]], playbook: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = []
    for step in steps:
        items.append({
            "type": "runtime_step",
            "title": step.get("title"),
            "decision": step.get("decision"),
            "blocked_at": step.get("blocked_at"),
            "rule_id": step.get("rule_id"),
            "detail": step.get("reason") or "步骤已完成运行时审计。",
        })
    for event in events[-4:]:
        items.append({
            "type": "event",
            "title": event.get("type") or event.get("event_type"),
            "stage": event.get("stage"),
            "status": event.get("status_label") or event.get("status"),
            "rule_id": event.get("rule_id"),
            "detail": event.get("detail"),
        })
    if not items:
        items.append({"type": "checkpoint", "title": "证据检查点", "detail": "暂无事件，请复核剧本执行链路。"})
    return items[:10]


def _remember_result(result: Dict[str, Any]) -> None:
    global _LAST_RESULTS
    _LAST_RESULTS = result
    store = _load_result_store()
    runs = [result] + [item for item in (store.get("runs") or []) if item.get("run_id") != result.get("run_id")]
    store["version"] = PLAYBOOK_VERSION
    store["runs"] = runs[:20]
    RESULT_STORE.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_result_store() -> Dict[str, Any]:
    if _LAST_RESULTS:
        try:
            store = json.loads(RESULT_STORE.read_text(encoding="utf-8")) if RESULT_STORE.exists() else {"runs": []}
        except Exception:
            store = {"runs": []}
        runs = [item for item in (store.get("runs") or []) if item.get("run_id") != _LAST_RESULTS.get("run_id")]
        return {"version": PLAYBOOK_VERSION, "runs": [_LAST_RESULTS] + runs}
    if not RESULT_STORE.exists():
        return {"version": PLAYBOOK_VERSION, "runs": []}
    try:
        return json.loads(RESULT_STORE.read_text(encoding="utf-8"))
    except Exception:
        return {"version": PLAYBOOK_VERSION, "runs": []}


def _surface_distribution(playbooks: List[Dict[str, Any]]) -> Dict[str, int]:
    return dict(Counter(item.get("attack_surface") or "Other" for item in playbooks))


def _result_surface_stats(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for item in results:
        surface = item.get("attack_surface") or "Other"
        row = grouped.setdefault(surface, {"surface": surface, "total": 0, "passed": 0, "failed": 0, "blocked_steps": 0})
        row["total"] += 1
        row["passed"] += 1 if item.get("passed") else 0
        row["failed"] += 0 if item.get("passed") else 1
        row["blocked_steps"] += sum(1 for step in item.get("steps") or [] if step.get("decision") == "blocked")
    rows = list(grouped.values())
    rows.sort(key=lambda item: (item["failed"], item["blocked_steps"], item["total"]), reverse=True)
    return rows


def _final_decision(decisions: List[str]) -> str:
    if "blocked" in decisions:
        return "blocked"
    if "confirm" in decisions:
        return "confirm"
    if "error" in decisions:
        return "error"
    if "timeout" in decisions:
        return "timeout"
    return "allowed" if decisions else "unknown"


def _final_blocked_at(blocked_at_values: List[str], decision: str) -> str:
    if decision == "allowed":
        return "none"
    for value in blocked_at_values:
        if value and value != "none":
            return value
    return "unknown"


def _normalize_decision(value: Any) -> str:
    text = str(value or "").lower()
    if text in {"block", "blocked", "deny"}:
        return "blocked"
    if text in {"confirm", "review", "pending", "ask"}:
        return "confirm"
    if text in {"timeout", "error"}:
        return text
    return "allowed" if text in {"allow", "allowed", "log", "passed"} else text or "unknown"


def _normalize_blocked_at(value: Any, decision: str) -> str:
    text = str(value or "").lower()
    if decision == "allowed":
        return "none"
    if text in {"detection", "input", "input_detection", "input_detected"}:
        return "detection"
    if text in {"policy", "policy_blocked", "policy_evaluated", "policy_confirm"}:
        return "policy"
    if text in {"tool", "tool_finished", "tool_started"}:
        return "tool"
    if text in {"output", "output_filter"}:
        return "output"
    if text in {"timeout", "error"}:
        return "error"
    return text or "unknown"


def _rule_from_steps(steps: List[Dict[str, Any]]) -> str:
    for step in steps:
        if step.get("rule_id"):
            return step.get("rule_id")
        evidence = step.get("evidence") or {}
        for item in evidence.get("matched_rules") or []:
            if item.get("id") or item.get("rule_id"):
                return item.get("id") or item.get("rule_id")
    return None


def _recommendation(playbook: Dict[str, Any], passed: bool, decision: str, blocked_at: str) -> str:
    if not passed:
        return "该剧本未完全满足回归断言，请复核命中规则、阻断阶段和证据检查点。"
    if decision == "blocked":
        return f"保持 {blocked_at} 阶段阻断，并将该剧本纳入持续回归。"
    if decision == "allowed":
        return "安全基线已放行且保留审计证据，可作为误报控制样本。"
    return "保留人工复核路径，并跟踪同类攻击面后续命中。"


def _next_action(results: List[Dict[str, Any]]) -> str:
    failed = next((item for item in results if not item.get("passed")), None)
    if failed:
        return f"优先复核 {failed.get('title')}，检查 chain_id、命中规则和回归断言。"
    return "攻击剧本回归全部达预期，可继续扩展真实业务 Agent 链路。"


def _severity_floor(severity: str) -> int:
    return {"critical": 90, "high": 75, "medium": 50, "low": 20}.get(str(severity or "").lower(), 40)


def _threat_from_severity(severity: str) -> str:
    return {"critical": "high", "high": "high", "medium": "medium", "low": "low"}.get(str(severity or "").lower(), "medium")


def _risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"
