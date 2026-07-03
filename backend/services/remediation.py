"""v4.8 remediation planning and closure records.

The remediation layer turns an evidence packet into an operator-facing action
plan. It is intentionally storage-light: suggested actions come from the
current evidence, while completed actions are appended to a small SQLite log.
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional

from runtime_paths import runtime_path


DB_PATH = runtime_path("ishield_remediation.db")
_db_lock = Lock()
_UTC8 = timezone(timedelta(hours=8))


ACTION_LABELS = {
    "contain_source": "隔离来源主体",
    "keep_block": "保持阻断策略",
    "add_regression": "加入回归样本",
    "review_pending": "复核确认队列",
    "reject_pending": "拒绝高风险调用",
    "approve_with_scope": "最小权限放行",
    "monitor_actor": "持续监控主体",
    "preserve_evidence": "保全证据链",
    "tighten_tool_scope": "收紧工具权限",
    "investigate_error": "排查异常阶段",
}


def init_db() -> None:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_actions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id    TEXT NOT NULL,
                action_id   TEXT NOT NULL,
                disposition TEXT NOT NULL,
                operator    TEXT,
                note        TEXT,
                created_at  TEXT NOT NULL
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_remediation_chain ON remediation_actions(chain_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_remediation_created ON remediation_actions(created_at DESC)")
        conn.commit()
        conn.close()


def build_remediation_plan(
    evidence_packet: Dict[str, Any],
    pending_items: Optional[List[Dict[str, Any]]] = None,
    action_records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    packet = evidence_packet or {}
    verdict = packet.get("verdict") or {}
    actors = packet.get("actors") or {}
    policy = packet.get("policy_evidence") or {}
    chain_id = packet.get("chain_id") or ""
    decision = _status_code(verdict.get("status_code"))
    blocked_at = verdict.get("blocked_at") or "unknown"
    risk_score = int(verdict.get("risk_score") or 0)
    pending_items = pending_items or []
    action_records = action_records or []
    pending_id = _pending_id(packet, pending_items)

    actions = _actions_for(decision, blocked_at, risk_score, actors, policy, pending_id)
    actions = _merge_action_records(actions, action_records)
    completed = sum(1 for item in actions if item.get("status") == "completed")
    required = [item for item in actions if item.get("required")]
    required_completed = sum(1 for item in required if item.get("status") == "completed")
    total = len(actions) or 1

    if decision in {"blocked", "confirm", "error"}:
        state = "closed" if required and required_completed == len(required) else "open"
    else:
        state = "monitored" if completed == 0 else "closed"

    next_action = next((item for item in actions if item.get("status") != "completed"), None)
    progress = round((completed / total) * 100)
    if required and state == "closed":
        progress = 100

    return {
        "version": "v4.8",
        "plan_id": _plan_id(chain_id, verdict, actors),
        "chain_id": chain_id,
        "state": state,
        "state_label": _state_label(state),
        "progress": progress,
        "requires_human": decision == "confirm",
        "pending_id": pending_id,
        "summary": _summary(decision, blocked_at, risk_score, actors),
        "next_action": next_action,
        "actions": actions,
        "stats": {
            "total": len(actions),
            "completed": completed,
            "required": len(required),
            "required_completed": required_completed,
        },
    }


def record_remediation_action(
    chain_id: str,
    action_id: str,
    disposition: str = "completed",
    operator: str = "operator",
    note: str = "",
) -> Dict[str, Any]:
    chain_id = str(chain_id or "").strip()
    action_id = str(action_id or "").strip()
    if not chain_id or not action_id:
        raise ValueError("chain_id and action_id are required")

    record = {
        "chain_id": chain_id,
        "action_id": action_id,
        "action_label": ACTION_LABELS.get(action_id, action_id),
        "disposition": str(disposition or "completed"),
        "operator": str(operator or "operator"),
        "note": str(note or ""),
        "created_at": _now_str(),
    }
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO remediation_actions
            (chain_id, action_id, disposition, operator, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                record["chain_id"],
                record["action_id"],
                record["disposition"],
                record["operator"],
                record["note"],
                record["created_at"],
            ),
        )
        record["id"] = c.lastrowid
        conn.commit()
        conn.close()
    return record


def list_remediation_actions(chain_id: str = None, limit: int = 100) -> List[Dict[str, Any]]:
    with _db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if chain_id:
            c.execute(
                "SELECT * FROM remediation_actions WHERE chain_id = ? ORDER BY id DESC LIMIT ?",
                (chain_id, limit),
            )
        else:
            c.execute("SELECT * FROM remediation_actions ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
    return [_row_to_dict(row) for row in rows]


def _actions_for(
    decision: str,
    blocked_at: str,
    risk_score: int,
    actors: Dict[str, Any],
    policy: Dict[str, Any],
    pending_id: str = None,
) -> List[Dict[str, Any]]:
    tool = actors.get("tool") or "--"
    target = actors.get("target") or "--"
    source = actors.get("source_ip") or "--"
    rule_id = actors.get("rule_id") or policy.get("rule_id") or "--"

    if decision == "blocked":
        return [
            _action("contain_source", "立即处置", True, "隔离同源 IP、Agent 或 Token，阻止重复触发同类工具调用。", source),
            _action("keep_block", "策略加固", True, f"保持 {blocked_at} 阶段阻断，复核命中规则 {rule_id} 是否覆盖同类变体。", rule_id),
            _action("add_regression", "持续验证", False, f"将 {tool} -> {target} 的载荷加入回归样本，后续版本自动复测。", tool),
        ]
    if decision == "confirm":
        return [
            _action("review_pending", "人工复核", True, "核对业务目的、操作者身份和参数范围，再决定确认或拒绝。", pending_id or "确认队列"),
            _action("reject_pending", "拒绝调用", False, "若无法证明业务必要性，拒绝该工具调用并保留审批记录。", pending_id or "--"),
            _action("approve_with_scope", "受控放行", False, f"必须执行时使用最小权限，只允许 {tool} 在限定目标内运行。", target),
        ]
    if decision == "error":
        return [
            _action("tighten_tool_scope", "临时收紧", True, f"临时收紧 {tool} 的执行范围，避免异常阶段扩大影响。", tool),
            _action("investigate_error", "异常排查", True, "检查运行时日志、沙箱返回和策略链路，定位失败阶段。", blocked_at),
            _action("preserve_evidence", "证据保全", False, "保留原始事件、trace_id 和调用参数，便于复盘。", source),
        ]
    return [
        _action("preserve_evidence", "审计保全", False, "保留全链路审计记录，支持后续追溯和统计分析。", tool),
        _action("monitor_actor", "持续监控", False, f"观察同源 {source} 的调用频率、目标变化和风险评分趋势。", source),
    ]


def _action(action_id: str, phase: str, required: bool, description: str, evidence: str = "") -> Dict[str, Any]:
    return {
        "action_id": action_id,
        "label": ACTION_LABELS.get(action_id, action_id),
        "phase": phase,
        "required": required,
        "status": "recommended" if required else "available",
        "status_label": "建议执行" if required else "可选动作",
        "description": description,
        "evidence": evidence,
    }


def _merge_action_records(actions: List[Dict[str, Any]], records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    latest = {}
    for record in sorted(records or [], key=lambda item: item.get("id") or 0):
        latest[record.get("action_id")] = record
    merged = []
    for action in actions:
        record = latest.get(action.get("action_id"))
        if record:
            action = dict(action)
            action["status"] = "completed" if record.get("disposition") == "completed" else record.get("disposition")
            action["status_label"] = "已执行" if action["status"] == "completed" else "已记录"
            action["record"] = record
        merged.append(action)
    return merged


def _pending_id(packet: Dict[str, Any], pending_items: List[Dict[str, Any]]) -> Optional[str]:
    for item in pending_items or []:
        if item.get("pending_id"):
            return item.get("pending_id")
    for item in packet.get("timeline") or []:
        evidence = item.get("evidence") or {}
        for value in (evidence, item):
            if isinstance(value, dict) and value.get("pending_id"):
                return value.get("pending_id")
    return None


def _status_code(value: Any) -> str:
    raw = str(value or "").lower()
    if raw in {"blocked", "confirm", "allowed", "passed", "error"}:
        return "allowed" if raw == "passed" else raw
    if raw in {"block", "deny", "rejected"}:
        return "blocked"
    if raw in {"ask", "pending", "review"}:
        return "confirm"
    return "allowed"


def _summary(decision: str, blocked_at: str, risk_score: int, actors: Dict[str, Any]) -> str:
    tool = actors.get("tool") or "工具调用"
    target = actors.get("target") or "目标"
    if decision == "blocked":
        return f"{tool} 已在 {blocked_at} 阶段被阻断，建议先隔离来源，再沉淀回归样本。"
    if decision == "confirm":
        return f"{tool} 命中确认策略，需完成审批记录后才能对 {target} 执行。"
    if decision == "error":
        return f"{tool} 出现异常处置状态，建议先收紧权限并保全证据。"
    if risk_score >= 45:
        return f"{tool} 已放行但风险分为 {risk_score}，建议持续观察同源主体。"
    return f"{tool} 已完成审计闭环，当前无需人工处置。"


def _state_label(state: str) -> str:
    return {
        "open": "待闭环",
        "closed": "已闭环",
        "monitored": "持续监控",
    }.get(state, "已记录")


def _plan_id(chain_id: str, verdict: Dict[str, Any], actors: Dict[str, Any]) -> str:
    seed = "|".join([
        str(chain_id or ""),
        str(verdict.get("status_code") or ""),
        str(actors.get("tool") or ""),
        str(actors.get("target") or ""),
    ])
    return "rem-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]


def _now_str() -> str:
    return datetime.now(_UTC8).strftime("%Y-%m-%d %H:%M:%S")


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    data = dict(row)
    data["action_label"] = ACTION_LABELS.get(data.get("action_id"), data.get("action_id"))
    return data


init_db()
