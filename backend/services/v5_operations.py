"""IShield v5.8 advanced operations services.

This module adds four product-facing capabilities without changing the
existing detection/runtime pipeline:

- v5.5 trace graph: rule -> event -> evidence -> response visibility.
- v5.6 response orchestration: runbook planning and controlled action records.
- v5.7 benchmark center: capability score from policy, runtime and playbooks.
- v5.8 system audit: delivery readiness checks for live operation.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from runtime_paths import bundled_path, runtime_data_dir, runtime_path, static_root
from services.events import get_chain_events, get_chain_summary, get_events_from_db, get_rule_hit_summary, get_stats
from services.playbook_engine import list_playbooks, regression_overview
from services.policy import get_policy_engine
from services.remediation import list_remediation_actions, record_remediation_action
from services.runtime_diagnostics import latest_diagnostic
from services.runtime_protocol import list_sessions


PRODUCT_VERSION = "v5.8"


def build_trace_graph(limit: int = 80, focus_chain_id: str = "") -> Dict[str, Any]:
    limit = _clamp(limit, 20, 200, 80)
    focus_chain_id = str(focus_chain_id or "").strip()
    events = get_chain_events(focus_chain_id) if focus_chain_id else get_events_from_db(limit=limit)
    chains = get_chain_summary(limit=30)
    rule_hits = get_rule_hit_summary(limit=3000, per_rule_limit=5)

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def node(node_id: str, label: str, kind: str, weight: int = 1, **extra: Any) -> None:
        if not node_id:
            return
        existing = nodes.setdefault(node_id, {"id": node_id, "label": label, "kind": kind, "weight": 0})
        existing["weight"] = int(existing.get("weight") or 0) + int(weight or 1)
        existing.update({k: v for k, v in extra.items() if v not in (None, "")})

    def edge(source: str, target: str, relation: str, weight: int = 1, **extra: Any) -> None:
        if not source or not target:
            return
        key = (source, target, relation)
        item = edges.setdefault(key, {"source": source, "target": target, "relation": relation, "weight": 0})
        item["weight"] = int(item.get("weight") or 0) + int(weight or 1)
        item.update({k: v for k, v in extra.items() if v not in (None, "")})

    node("system:ishield", "IShield 监督平面", "system", 5, status="active")
    for hit in rule_hits[:30]:
        rid = str(hit.get("rule_id") or "").strip()
        if not rid:
            continue
        node(f"rule:{rid}", rid, "rule", int(hit.get("hit_count") or 1), hit_count=hit.get("hit_count"))
        edge("system:ishield", f"rule:{rid}", "governs", 1)

    for chain in chains[:30]:
        cid = str(chain.get("chain_id") or "").strip()
        if not cid:
            continue
        node(
            f"chain:{cid}",
            cid,
            "chain",
            int(chain.get("event_count") or 1),
            status_code=chain.get("status_code"),
            risk_score=chain.get("max_confidence") or 0,
        )
        edge("system:ishield", f"chain:{cid}", "observes", 1)
        rule_id = ((chain.get("evidence_packet") or {}).get("policy_evidence") or {}).get("rule_id")
        if rule_id:
            node(f"rule:{rule_id}", rule_id, "rule", 1)
            edge(f"rule:{rule_id}", f"chain:{cid}", "triggered", 1)
        remediation = chain.get("remediation") or {}
        if remediation:
            state = remediation.get("state") or "open"
            node(f"response:{state}", _response_state_label(state), "response", 1, progress=remediation.get("progress"))
            edge(f"chain:{cid}", f"response:{state}", "requires_response", 1)

    for event in events[:limit]:
        event_id = str(event.get("id") or "")
        chain_id = str(event.get("chain_id") or "").strip()
        rule_id = str(event.get("rule_id") or "").strip()
        tool = str(event.get("tool_name") or event.get("action") or "").strip()
        source_ip = str(event.get("source_ip") or "").strip()
        status_code = event.get("status_code") or "unknown"

        node(f"event:{event_id}", f"事件 {event_id}", "event", 1, status_code=status_code, time=event.get("time"))
        edge("system:ishield", f"event:{event_id}", "records", 1)
        if chain_id:
            node(f"chain:{chain_id}", chain_id, "chain", 1)
            edge(f"chain:{chain_id}", f"event:{event_id}", "contains", 1)
        if rule_id:
            node(f"rule:{rule_id}", rule_id, "rule", 1)
            edge(f"rule:{rule_id}", f"event:{event_id}", "matched", 1)
        if tool:
            node(f"tool:{tool}", tool, "tool", 1)
            edge(f"event:{event_id}", f"tool:{tool}", "uses_tool", 1)
        if source_ip:
            node(f"actor:{source_ip}", source_ip, "actor", 1)
            edge(f"actor:{source_ip}", f"event:{event_id}", "initiates", 1)
        node(f"verdict:{status_code}", _status_label(status_code), "verdict", 1)
        edge(f"event:{event_id}", f"verdict:{status_code}", "decides", 1)

    node_list = sorted(nodes.values(), key=lambda item: (item.get("kind") != "system", -int(item.get("weight") or 0), item.get("id", "")))
    edge_list = sorted(edges.values(), key=lambda item: -int(item.get("weight") or 0))
    return {
        "version": "v5.5",
        "generated_at": _now(),
        "focus_chain_id": focus_chain_id,
        "summary": {
            "node_count": len(node_list),
            "edge_count": len(edge_list),
            "event_count": len(events),
            "chain_count": len([n for n in node_list if n.get("kind") == "chain"]),
            "rule_count": len([n for n in node_list if n.get("kind") == "rule"]),
        },
        "hotspots": _trace_hotspots(events, rule_hits),
        "nodes": node_list[:160],
        "edges": edge_list[:260],
        "recent_events": [_event_brief(item) for item in events[:12]],
        "priority_chains": [_chain_brief(item) for item in chains[:8]],
    }


def search_trace(query: str = "", limit: int = 30) -> Dict[str, Any]:
    query = str(query or "").strip().lower()
    limit = _clamp(limit, 5, 100, 30)
    events = get_events_from_db(limit=300)
    if query:
        events = [
            item for item in events
            if query in " ".join(str(item.get(k) or "") for k in ("id", "type", "detail", "rule_id", "chain_id", "tool_name", "target", "source_ip")).lower()
        ]
    chains = []
    seen = set()
    for event in events:
        cid = event.get("chain_id")
        if cid and cid not in seen:
            seen.add(cid)
            chain_events = get_chain_events(cid)
            chains.append({"chain_id": cid, "event_count": len(chain_events), "events": [_event_brief(e) for e in chain_events[:8]]})
        if len(chains) >= limit:
            break
    return {
        "version": "v5.5",
        "query": query,
        "count": min(len(events), limit),
        "events": [_event_brief(item) for item in events[:limit]],
        "chains": chains,
    }


def build_response_center(limit: int = 30) -> Dict[str, Any]:
    chains = get_chain_summary(limit=_clamp(limit, 10, 80, 30))
    actions = list_remediation_actions(limit=120)
    action_counter = Counter(item.get("action_id") or "unknown" for item in actions)
    open_chains = [item for item in chains if item.get("status_code") in {"blocked", "confirm", "error"} and ((item.get("remediation") or {}).get("state") != "closed")]
    runbooks = _runbooks()
    recommendations = [_recommend_runbook(chain, runbooks) for chain in open_chains[:10]]
    return {
        "version": "v5.6",
        "generated_at": _now(),
        "summary": {
            "runbook_count": len(runbooks),
            "open_chain_count": len(open_chains),
            "recorded_actions": len(actions),
            "completed_actions": sum(1 for item in actions if item.get("disposition") == "completed"),
        },
        "runbooks": runbooks,
        "recommendations": recommendations,
        "recent_actions": actions[:20],
        "action_distribution": [{"action_id": key, "count": value} for key, value in action_counter.most_common(12)],
    }


def execute_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = payload or {}
    chain_id = str(payload.get("chain_id") or "").strip()
    runbook_id = str(payload.get("runbook_id") or "containment-standard").strip()
    dry_run = payload.get("dry_run", True) is not False
    operator = str(payload.get("operator") or "IShield Orchestrator").strip()
    runbook = next((item for item in _runbooks() if item["id"] == runbook_id), _runbooks()[0])
    planned = []
    recorded = []
    for step in runbook.get("steps", []):
        action_id = step.get("action_id")
        planned.append({"action_id": action_id, "label": step.get("label"), "required": step.get("required"), "phase": step.get("phase")})
        if chain_id and not dry_run:
            recorded.append(record_remediation_action(chain_id, action_id, operator=operator, note=f"Runbook {runbook_id}: {step.get('label')}"))
    return {
        "version": "v5.6",
        "generated_at": _now(),
        "mode": "dry_run" if dry_run else "recorded",
        "chain_id": chain_id,
        "runbook": runbook,
        "planned_actions": planned,
        "records": recorded,
        "next_action": "确认处置动作后可写入闭环记录。" if dry_run else "处置动作已写入闭环记录，可回到事件中心查看进度。",
    }


def build_benchmark_overview() -> Dict[str, Any]:
    policy_summary = get_policy_engine().summary()
    playbooks = list_playbooks()
    regression = regression_overview()
    diagnostic = latest_diagnostic()
    stats = get_stats()
    dimensions = _benchmark_dimensions(policy_summary, playbooks, regression, diagnostic, stats)
    score = round(sum(item["score"] * item["weight"] for item in dimensions) / sum(item["weight"] for item in dimensions), 1)
    return {
        "version": "v5.7",
        "generated_at": _now(),
        "score": score,
        "grade": _grade(score),
        "dimensions": dimensions,
        "summary": {
            "policy_rules": policy_summary.get("total", 0),
            "attack_surfaces": len(policy_summary.get("category_distribution") or {}),
            "playbooks": playbooks.get("count", 0),
            "runtime_sessions": list_sessions(limit=1).get("count", 0),
            "events": stats.get("total", 0),
        },
        "next_actions": _benchmark_next_actions(dimensions),
    }


def run_benchmark(payload: Dict[str, Any] = None) -> Dict[str, Any]:
    payload = payload or {}
    overview = build_benchmark_overview()
    rules = get_policy_engine().all_rules
    sampled_cases = 0
    policy_hits = 0
    for rule in rules:
        for case in (getattr(rule, "test_cases", None) or [])[:2]:
            sampled_cases += 1
            try:
                result = get_policy_engine().evaluate(case.get("tool") or rule.tool.split("|")[0], case.get("params") or case.get("tool_args") or {})
                if result.triggered_rule == rule.id or result.action.value == rule.action.value:
                    policy_hits += 1
            except Exception:
                continue
    policy_accuracy = round((policy_hits / sampled_cases) * 100, 1) if sampled_cases else 0
    overview["run_id"] = str(payload.get("run_id") or f"bench-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    overview["mode"] = "benchmark"
    overview["policy_sample"] = {"case_count": sampled_cases, "hit_count": policy_hits, "accuracy": policy_accuracy}
    overview["score"] = round((overview["score"] * 0.75) + (policy_accuracy * 0.25), 1) if sampled_cases else overview["score"]
    overview["grade"] = _grade(overview["score"])
    return overview


def build_system_audit() -> Dict[str, Any]:
    root = bundled_path()
    checks = [
        _file_check("主前端", static_root() / "frontend.html", min_size=200000),
        _file_check("态势大屏", static_root() / "dashboard.html", min_size=30000),
        _file_check("规则库", bundled_path("backend", "policies", "default_policy.json"), min_size=50000),
        _file_check("攻击剧本", bundled_path("backend", "playbooks", "default_playbooks.json"), min_size=10000),
        _file_check("Globe.gl", static_root() / "assets" / "vendor" / "globe" / "globe.gl.min.js", min_size=500000),
        _file_check("地球纹理", static_root() / "assets" / "vendor" / "globe" / "earth-night.jpg", min_size=100000),
        _runtime_check("运行数据目录", runtime_data_dir()),
        _runtime_check("事件数据库", runtime_path("ishield.db")),
    ]
    stats = get_stats()
    policy = get_policy_engine().summary()
    regression = regression_overview()
    diagnostic = latest_diagnostic()
    checks.extend([
        _value_check("规则库规模", int(policy.get("total") or 0) >= 60, f"{policy.get('total', 0)} 条规则"),
        _value_check("事件链路", int(stats.get("chain_total") or 0) > 0, f"{stats.get('chain_total', 0)} 条 chain_id"),
        _value_check("Playbook 回归", regression.get("status") != "empty", "已有结果" if regression.get("status") != "empty" else "等待运行"),
        _value_check("Runtime 诊断", diagnostic.get("status") != "empty", "已有结果" if diagnostic.get("status") != "empty" else "等待运行"),
    ])
    passed = sum(1 for item in checks if item["status"] == "passed")
    warnings = sum(1 for item in checks if item["status"] == "warning")
    failed = sum(1 for item in checks if item["status"] == "failed")
    readiness = round((passed / len(checks)) * 100, 1) if checks else 0
    return {
        "version": "v5.8",
        "generated_at": _now(),
        "readiness": readiness,
        "state": "ready" if failed == 0 and readiness >= 80 else "attention",
        "summary": {
            "checks": len(checks),
            "passed": passed,
            "warnings": warnings,
            "failed": failed,
            "workspace": str(root),
        },
        "checks": checks,
        "release": {
            "current": "v5.8.0",
            "baseline": ["v5.5 trace graph", "v5.6 response orchestration", "v5.7 benchmark center", "v5.8 system audit"],
            "experience_path": "左侧功能列表进入：证据图谱、处置编排、能力评测、系统体检。",
        },
    }


def _runbooks() -> List[Dict[str, Any]]:
    return [
        {
            "id": "containment-standard",
            "title": "高危链路隔离",
            "surface": "工具越权 / 文件访问 / 数据外发",
            "severity": "high",
            "goal": "将已阻断链路转化为可追踪闭环，保留证据并收紧同源调用。",
            "steps": [
                {"action_id": "contain_source", "label": "隔离同源 Agent/IP/Token", "phase": "隔离", "required": True},
                {"action_id": "keep_block", "label": "保持阻断策略并复核命中规则", "phase": "加固", "required": True},
                {"action_id": "add_regression", "label": "加入回归样本", "phase": "回归", "required": False},
            ],
        },
        {
            "id": "approval-min-scope",
            "title": "确认队列最小授权",
            "surface": "高敏确认 / 管理操作",
            "severity": "medium",
            "goal": "对需要确认的调用建立可审计授权边界。",
            "steps": [
                {"action_id": "review_pending", "label": "复核业务目的和参数范围", "phase": "复核", "required": True},
                {"action_id": "approve_with_scope", "label": "仅在限定范围内放行", "phase": "授权", "required": False},
                {"action_id": "preserve_evidence", "label": "保全审批证据", "phase": "审计", "required": True},
            ],
        },
        {
            "id": "runtime-exception",
            "title": "运行时异常收敛",
            "surface": "代码执行 / 沙箱异常 / 工具超时",
            "severity": "high",
            "goal": "将异常链路收敛到可复盘的运行时证据。",
            "steps": [
                {"action_id": "tighten_tool_scope", "label": "临时收紧工具范围", "phase": "控制", "required": True},
                {"action_id": "investigate_error", "label": "定位失败阶段", "phase": "诊断", "required": True},
                {"action_id": "preserve_evidence", "label": "保留 trace_id 与参数", "phase": "审计", "required": False},
            ],
        },
    ]


def _recommend_runbook(chain: Dict[str, Any], runbooks: List[Dict[str, Any]]) -> Dict[str, Any]:
    status = chain.get("status_code")
    if status == "confirm":
        runbook = runbooks[1]
    elif status == "error":
        runbook = runbooks[2]
    else:
        runbook = runbooks[0]
    return {
        "chain_id": chain.get("chain_id"),
        "status_code": status,
        "risk_score": chain.get("max_confidence") or 0,
        "tool": chain.get("tool_name") or chain.get("action"),
        "target": chain.get("target"),
        "runbook_id": runbook["id"],
        "runbook_title": runbook["title"],
        "reason": chain.get("runtime_conclusion") or chain.get("recommendation") or "该链路需要处置闭环。",
    }


def _benchmark_dimensions(policy_summary: Dict[str, Any], playbooks: Dict[str, Any], regression: Dict[str, Any], diagnostic: Dict[str, Any], stats: Dict[str, Any]) -> List[Dict[str, Any]]:
    regression_summary = regression.get("summary") or {}
    diagnostic_summary = diagnostic.get("summary") or diagnostic
    dimensions = [
        {"key": "policy", "label": "规则覆盖", "score": min(100, round((policy_summary.get("total", 0) / 69) * 100, 1)), "weight": 1.2, "evidence": f"{policy_summary.get('total', 0)} 条规则"},
        {"key": "surface", "label": "攻击面", "score": min(100, len(policy_summary.get("category_distribution") or {}) * 8), "weight": 1.0, "evidence": f"{len(policy_summary.get('category_distribution') or {})} 类攻击面"},
        {"key": "runtime", "label": "Agent 接入", "score": diagnostic_summary.get("coverage", 0) if isinstance(diagnostic_summary, dict) else 0, "weight": 1.0, "evidence": "Runtime Protocol 诊断"},
        {"key": "playbook", "label": "多阶段红队", "score": regression_summary.get("coverage", 0) if regression_summary else min(100, playbooks.get("count", 0) * 8), "weight": 1.2, "evidence": f"{playbooks.get('count', 0)} 个剧本"},
        {"key": "evidence", "label": "证据链", "score": 100 if stats.get("chain_total", 0) else 40, "weight": 1.0, "evidence": f"{stats.get('chain_total', 0)} 条攻击链"},
        {"key": "response", "label": "处置闭环", "score": 90 if list_remediation_actions(limit=1) else 60, "weight": 0.8, "evidence": "Remediation Loop"},
    ]
    return dimensions


def _benchmark_next_actions(dimensions: List[Dict[str, Any]]) -> List[str]:
    weak = [item for item in dimensions if float(item.get("score") or 0) < 80]
    if not weak:
        return ["保持当前基线，定期运行能力评测和攻击剧本回归。"]
    return [f"补强{item['label']}：{item['evidence']}" for item in weak[:4]]


def _trace_hotspots(events: List[Dict[str, Any]], rule_hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    tools = Counter((item.get("tool_name") or item.get("action") or "unknown") for item in events)
    statuses = Counter(item.get("status_code") or "unknown" for item in events)
    return {
        "top_tools": [{"name": key, "count": value} for key, value in tools.most_common(6)],
        "status_distribution": [{"name": _status_label(key), "code": key, "count": value} for key, value in statuses.most_common()],
        "top_rules": [{"rule_id": item.get("rule_id"), "count": item.get("hit_count") or 0} for item in rule_hits[:6]],
    }


def _file_check(label: str, path: Path, min_size: int = 1) -> Dict[str, Any]:
    exists = path.is_file()
    size = path.stat().st_size if exists else 0
    ok = exists and size >= min_size
    return {
        "id": label,
        "label": label,
        "status": "passed" if ok else ("warning" if exists else "failed"),
        "detail": f"{size} bytes" if exists else "文件不存在",
        "path": str(path),
    }


def _runtime_check(label: str, path: Path) -> Dict[str, Any]:
    exists = path.exists()
    return {"id": label, "label": label, "status": "passed" if exists else "warning", "detail": "可用" if exists else "等待生成", "path": str(path)}


def _value_check(label: str, ok: bool, detail: str) -> Dict[str, Any]:
    return {"id": label, "label": label, "status": "passed" if ok else "warning", "detail": detail}


def _event_brief(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": event.get("id"),
        "time": event.get("time"),
        "type": event.get("type"),
        "detail": event.get("detail"),
        "status_code": event.get("status_code"),
        "status_label": event.get("status_label"),
        "rule_id": event.get("rule_id"),
        "chain_id": event.get("chain_id"),
        "tool": event.get("tool_name") or event.get("action"),
        "target": event.get("target"),
    }


def _chain_brief(chain: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "chain_id": chain.get("chain_id"),
        "status_code": chain.get("status_code"),
        "status_label": chain.get("status_label"),
        "risk_score": chain.get("max_confidence") or 0,
        "tool": chain.get("tool_name") or chain.get("action"),
        "target": chain.get("target"),
        "summary": chain.get("runtime_conclusion") or chain.get("recommendation"),
    }


def _status_label(code: str) -> str:
    return {"blocked": "已阻断", "confirm": "待确认", "allowed": "已放行", "error": "异常", "running": "运行中", "review": "已复核"}.get(str(code or "unknown"), "未知")


def _response_state_label(state: str) -> str:
    return {"open": "待处置", "closed": "已闭环", "monitored": "监控中"}.get(str(state or ""), "处置")


def _grade(score: float) -> str:
    if score >= 92:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B+"
    if score >= 65:
        return "B"
    return "C"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp(value: Any, lower: int, upper: int, default: int) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))
