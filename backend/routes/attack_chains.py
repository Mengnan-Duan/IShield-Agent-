"""攻击链关联分析路由"""
from flask import Blueprint, request
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.attack_chain_analyzer import (
    get_attack_chains_summary,
    detect_multi_stage_attack,
    classify_attack_pattern,
)
from services.events import get_chain_events, get_chain_summary, normalize_status, status_label

chains_bp = Blueprint("chains", __name__, url_prefix="/api/chains")


@chains_bp.route("", methods=["GET"])
def list_chains():
    """GET /api/chains — 攻击链列表（带 limit）"""
    limit = int(request.args.get("limit", 50))
    chains = get_chain_summary(limit=limit)
    return make_response({"chains": chains, "total": len(chains)})


@chains_bp.route("/summary", methods=["GET"])
def chains_summary():
    """GET /api/chains/summary — 全局攻击链摘要"""
    result = get_attack_chains_summary()
    return make_response(result)


@chains_bp.route("/<chain_id>", methods=["GET"])
def chain_detail(chain_id: str):
    """GET /api/chains/<chain_id> — 单条攻击链详情"""
    events = get_chain_events(chain_id)
    if not events:
        raise ValidationError(f"未找到 chain_id={chain_id} 的事件")

    analysis = detect_multi_stage_attack(chain_id)

    # 获取链汇总信息（包含 status/source_ip 等）
    summaries = get_chain_summary(limit=1000)
    chain_info = next((s for s in summaries if s.get("chain_id") == chain_id), None)
    if not chain_info:
        chain_info = {"chain_id": chain_id}

    return make_response({
        "chain": chain_info,
        "chain_id": chain_id,
        "events": events,
        "analysis": analysis,
    })


@chains_bp.route("/<chain_id>/replay", methods=["GET"])
def chain_replay(chain_id: str):
    """GET /api/chains/<chain_id>/replay — normalized runtime replay for UI."""
    events = get_chain_events(chain_id)
    if not events:
        raise ValidationError(f"未找到 chain_id={chain_id} 的事件")

    replay = build_chain_replay(chain_id, events)
    return make_response(replay, chain_id=chain_id)


def build_chain_replay(chain_id: str, events: list) -> dict:
    conclusion = _latest_runtime_conclusion(events)
    metadata = conclusion.get("metadata") if conclusion else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    runtime_steps = metadata.get("steps") if isinstance(metadata.get("steps"), list) else []
    tool_evidence = metadata.get("tool_evidence") if isinstance(metadata.get("tool_evidence"), dict) else None
    risk_assessment = metadata.get("risk_assessment") if isinstance(metadata.get("risk_assessment"), dict) else None

    decision = (
        metadata.get("decision")
        or (tool_evidence or {}).get("decision")
        or (conclusion or {}).get("status_code")
        or _chain_status_code(events)
    )
    blocked_at = metadata.get("blocked_at") or (tool_evidence or {}).get("blocked_at") or _blocked_at_from_steps(runtime_steps)
    risk_score = max((int(e.get("confidence") or 0) for e in events), default=0)
    if conclusion and conclusion.get("confidence") is not None:
        risk_score = max(risk_score, int(conclusion.get("confidence") or 0))
    if risk_assessment:
        risk_score = max(risk_score, int(risk_assessment.get("risk_score") or 0))

    flow = _build_replay_flow(runtime_steps, decision, blocked_at)
    primary = conclusion or events[-1]
    status_code = normalize_status(status_label(decision), None, {"decision": decision})

    return {
        "chain_id": chain_id,
        "decision": decision,
        "status": status_label(status_code),
        "status_code": status_code,
        "blocked_at": blocked_at,
        "risk_score": risk_score,
        "risk_level": (conclusion or {}).get("threat_level") or _risk_level(risk_score),
        "source_ip": primary.get("source_ip"),
        "action": primary.get("action"),
        "tool_name": primary.get("tool_name"),
        "target": primary.get("target"),
        "summary": (tool_evidence or {}).get("summary") or (conclusion or {}).get("detail") or "攻击链已完成运行时审计。",
        "recommendation": (tool_evidence or {}).get("recommendation") or _recommendation_for_decision(decision, blocked_at),
        "risk_assessment": risk_assessment,
        "risk_factors": (risk_assessment or {}).get("risk_factors", []),
        "flow": flow,
        "runtime_steps": runtime_steps,
        "tool_evidence": tool_evidence,
        "events": events,
        "event_count": len(events),
        "conclusion_event_id": conclusion.get("id") if conclusion else None,
    }


def _latest_runtime_conclusion(events: list) -> dict:
    for event in sorted(events or [], key=lambda item: item.get("id") or 0, reverse=True):
        meta = event.get("metadata") or {}
        if event.get("stage") == "runtime_conclusion" or event.get("category") == "runtime_conclusion" or isinstance(meta.get("steps"), list):
            return event
    return None


def _chain_status_code(events: list) -> str:
    codes = {event.get("status_code") or normalize_status(event.get("status"), event.get("stage"), event.get("metadata")) for event in events}
    if "blocked" in codes:
        return "blocked"
    if "confirm" in codes:
        return "confirm"
    if "error" in codes:
        return "error"
    if "running" in codes:
        return "running"
    return "allowed"


def _blocked_at_from_steps(steps: list) -> str:
    for step in steps or []:
        if normalize_status(step.get("status")) in {"blocked", "confirm", "error"}:
            stage = step.get("stage") or ""
            if "detection" in stage:
                return "detection"
            if "policy" in stage:
                return "policy"
            if "tool" in stage:
                return "tool"
            return stage or "unknown"
    return "none"


def _build_replay_flow(steps: list, decision: str, blocked_at: str) -> list:
    gate_defs = [
        ("request", "请求接入", "request_received"),
        ("detection", "意图检测", "input_detection"),
        ("policy", "策略裁决", "policy_evaluated"),
        ("tool", "工具沙箱", "tool_finished"),
        ("conclusion", "最终结论", "runtime_conclusion"),
    ]
    step_map = {}
    for step in steps or []:
        stage = step.get("stage") or ""
        if stage == "request_received":
            step_map["request"] = step
        elif "detection" in stage:
            step_map["detection"] = step
        elif "policy" in stage:
            step_map["policy"] = step
        elif "tool" in stage:
            step_map["tool"] = step

    flow = []
    for key, title, stage_name in gate_defs:
        if key == "conclusion":
            status = decision
            detail = _conclusion_detail(decision, blocked_at)
            risk_score = max((int(step.get("risk_score") or 0) for step in steps or []), default=0)
        else:
            step = step_map.get(key)
            if step:
                status = normalize_status(step.get("status"))
                if key == "request" and status == "running":
                    status = "passed"
                detail = step.get("detail") or "该阶段已完成审计。"
                risk_score = int(step.get("risk_score") or 0)
            elif key == "tool" and blocked_at in {"detection", "policy"}:
                status = "skipped"
                detail = "前置阶段已完成阻断，工具未被执行。"
                risk_score = 0
            else:
                status = "pending"
                detail = "该阶段未产生独立记录。"
                risk_score = 0
        flow.append({
            "key": key,
            "stage": stage_name,
            "title": title,
            "status": status,
            "status_label": _flow_status_label(status),
            "detail": detail,
            "risk_score": risk_score,
            "highlight": key == blocked_at or (key == "conclusion" and decision in {"blocked", "confirm", "error"}),
        })
    return flow


def _flow_status_label(status: str) -> str:
    return {
        "blocked": "已阻断",
        "confirm": "需确认",
        "allowed": "已放行",
        "passed": "已通过",
        "running": "处理中",
        "error": "异常",
        "skipped": "未执行",
        "pending": "未记录",
    }.get(status, status_label(normalize_status(status)))


def _conclusion_detail(decision: str, blocked_at: str) -> str:
    if decision == "blocked":
        return f"链路在 {blocked_at or 'runtime'} 阶段完成阻断。"
    if decision == "confirm":
        return "链路已进入人工确认队列。"
    if decision == "allowed":
        return "链路通过检测、策略和工具沙箱审计。"
    if decision == "error":
        return "链路执行出现异常，已记录审计证据。"
    return "链路已生成运行时结论。"


def _recommendation_for_decision(decision: str, blocked_at: str) -> str:
    if decision == "blocked":
        return f"保持 {blocked_at or 'runtime'} 阶段阻断策略，并将本次样本加入回归验证集。"
    if decision == "confirm":
        return "保留当前确认队列策略，补充审批人、审批原因和执行后审计记录。"
    if decision == "allowed":
        return "保留全链路审计记录，持续观察相同来源的后续工具调用。"
    return "排查异常阶段日志，必要时降级工具权限并重放链路。"


def _risk_level(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 45:
        return "medium"
    if score > 0:
        return "low"
    return "none"
