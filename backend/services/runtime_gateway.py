"""Runtime gateway for auditable Agent tool calls."""
import json
import os
import re
import sys
import uuid
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.detection import hybrid_detect
from services.events import add_event
from services.policy import Action, get_policy_engine, serialize_policy_result
from services.risk_engine import get_risk_engine
from services.rule_engine import rule_detect
from services.websocket import broadcast_alert
from tools.tool_runner import run_tool


POLICY_MESSAGES = {
    "POL-DROP-TABLE": "检测到高危数据库写操作，已阻断执行。",
    "POL-SQL-INJECTION": "检测到 SQL 注入模式，已阻断执行。",
    "POL-PASSWORD-QUERY": "查询包含敏感字段，需要人工确认。",
    "POL-PHISHING-URL": "检测到疑似钓鱼或外联诱导内容，已阻断发送。",
    "POL-FILE-PATH-TRAVERSAL": "检测到路径遍历攻击，已阻断文件访问。",
    "POL-SYSTEM-FILE": "禁止读取系统敏感文件。",
    "POL-API-KEY-EXPOSURE": "检测到密钥或令牌外发风险，已阻断请求。",
    "POL-ADMIN-ACCOUNT": "涉及管理员账户操作，需要人工确认。",
}


def execute_runtime_request(
    action: str,
    params: Any,
    chain_id: str = None,
    source_ip: str = None,
    token_meta: dict = None,
    trace_id: str = None,
    actor: str = "agent",
    fast_detection: bool = False,
    user_input: str = "",
) -> dict:
    """Execute one Agent tool call through detection, policy and sandbox layers."""
    action = str(action or "").strip()
    params_text, parsed_params = _normalize_params(params)
    chain_id = chain_id or f"chain-{uuid.uuid4().hex[:12]}"
    trace_id = trace_id or str(uuid.uuid4())[:16]
    source_ip = source_ip or "127.0.0.1"
    target = _extract_target(action, parsed_params, params_text)
    steps: List[Dict[str, Any]] = []

    _add_step(
        steps,
        "request_received",
        "请求接入",
        "running",
        f"工具={action}, 目标={target or '-'}",
        risk_score=0,
    )
    add_event(
        event_type="运行时请求",
        detail=f"工具={action}, 目标={target or '-'}",
        status="分析中",
        source_ip=source_ip,
        action=action,
        tool_name=action,
        target=target,
        category="runtime_gateway",
        threat_level="low",
        confidence=0,
        chain_id=chain_id,
        stage="request_received",
        metadata={
            "params": _preview(parsed_params),
            "trace_id": trace_id,
            "actor": actor,
            "user_input_preview": _preview(user_input, 240) if user_input else "",
        },
    )

    context = _build_detection_context(action, params_text, parsed_params, user_input=user_input)
    is_malicious, reason, confidence = _safe_hybrid_detect(context, fast=fast_detection)
    risk_score = _confidence_score(confidence)
    threat_level = _threat_level(confidence, "high" if is_malicious else "low")
    _add_step(
        steps,
        "input_detection",
        "意图检测",
        "blocked" if is_malicious else "passed",
        reason if is_malicious else "未发现明确注入或越权意图。",
        risk_score=risk_score,
    )

    if is_malicious:
        risk_assessment = get_risk_engine().score_runtime(
            action=action,
            target=target,
            decision="blocked",
            blocked_at="input",
            input_score=risk_score,
            source_ip=source_ip,
            token=_token_id(token_meta),
            session=chain_id,
            chain_id=chain_id,
            actor=actor,
        )
        risk_score = max(risk_score, int(risk_assessment.get("risk_score") or 0))
        threat_level = risk_assessment.get("risk_level") or threat_level
        add_event(
            event_type="检测阻断",
            detail=f"工具={action}, 原因={reason}",
            status="已阻断",
            source_ip=source_ip,
            action=action,
            tool_name=action,
            target=target,
            category="prompt_injection",
            threat_level=threat_level,
            confidence=risk_score,
            chain_id=chain_id,
            stage="detection_blocked",
            metadata={"reason": reason, "params": _preview(parsed_params), "trace_id": trace_id},
        )
        _broadcast_runtime_alert("检测阻断", action, "已阻断", threat_level, risk_score, source_ip, target, chain_id, reason)
        _add_runtime_conclusion(
            action=action,
            target=target,
            decision="blocked",
            reason=f"检测到高风险输入：{reason}",
            source_ip=source_ip,
            chain_id=chain_id,
            trace_id=trace_id,
            risk_level=threat_level,
            risk_score=risk_score,
            steps=steps,
            blocked_at="detection",
            risk_assessment=risk_assessment,
        )
        return _runtime_result(
            result="blocked",
            decision="blocked",
            blocked_at="detection",
            reason=f"检测到高风险输入：{reason}",
            action=action,
            params=parsed_params,
            source_ip=source_ip,
            target=target,
            chain_id=chain_id,
            trace_id=trace_id,
            risk_level=threat_level,
            risk_score=risk_score,
            risk_assessment=risk_assessment,
            steps=steps,
        )

    engine = get_policy_engine()
    policy_result = engine.evaluate(action, params_text)
    policy_trace = serialize_policy_result(policy_result)
    policy_message = _policy_message(policy_result)
    policy_status = "passed"
    if policy_result.action == Action.BLOCK:
        policy_status = "blocked"
    elif policy_result.action == Action.CONFIRM:
        policy_status = "confirm"

    _add_step(
        steps,
        "policy_evaluated",
        "策略裁决",
        policy_status,
        policy_message or "策略允许执行。",
        risk_score=policy_result.severity,
        rule_id=policy_result.triggered_rule,
        evidence={
            "policy_trace": policy_trace,
            "matched_rules": policy_trace.get("matched_rules", []),
            "recommendation": policy_trace.get("recommendation", ""),
        },
    )
    add_event(
        event_type="策略裁决",
        detail=f"工具={action}, 动作={policy_result.action.value}, 规则={policy_result.triggered_rule or '-'}",
        status="已评估",
        source_ip=source_ip,
        action=action,
        tool_name=action,
        target=target,
        rule_id=policy_result.triggered_rule,
        category="policy_evaluation",
        threat_level="medium" if policy_result.action == Action.CONFIRM else ("high" if policy_result.action == Action.BLOCK else "low"),
        confidence=policy_result.severity,
        chain_id=chain_id,
        stage="policy_evaluated",
        metadata={
            "message": policy_message,
            "matched_keywords": policy_result.matched_keywords,
            "decision": policy_result.action.value,
            "policy_trace": policy_trace,
            "trace_id": trace_id,
        },
    )

    if policy_result.action == Action.BLOCK:
        risk_assessment = get_risk_engine().score_runtime(
            action=action,
            target=target,
            decision="blocked",
            blocked_at="policy",
            input_score=risk_score,
            policy_trace=policy_trace,
            source_ip=source_ip,
            token=_token_id(token_meta),
            session=chain_id,
            chain_id=chain_id,
            actor=actor,
        )
        final_risk_score = max(policy_result.severity, risk_score, int(risk_assessment.get("risk_score") or 0))
        final_risk_level = risk_assessment.get("risk_level") or "high"
        add_event(
            event_type="策略阻断",
            detail=f"工具={action}, 规则={policy_result.triggered_rule}, 原因={policy_message}",
            status="已阻断",
            source_ip=source_ip,
            action=action,
            tool_name=action,
            target=target,
            rule_id=policy_result.triggered_rule,
            category="policy_violation",
            threat_level=final_risk_level,
            confidence=final_risk_score,
            chain_id=chain_id,
            stage="policy_blocked",
            metadata={"message": policy_message, "trace_id": trace_id, "policy_trace": policy_trace},
        )
        _broadcast_runtime_alert("策略阻断", action, "已阻断", "high", policy_result.severity, source_ip, target, chain_id, policy_message)
        _add_runtime_conclusion(
            action=action,
            target=target,
            decision="blocked",
            reason=policy_message,
            source_ip=source_ip,
            chain_id=chain_id,
            trace_id=trace_id,
            risk_level="high",
            risk_score=final_risk_score,
            steps=steps,
            blocked_at="policy",
            rule_id=policy_result.triggered_rule,
            extra={"policy_trace": policy_trace},
            risk_assessment=risk_assessment,
        )
        return _runtime_result(
            result="blocked",
            decision="blocked",
            blocked_at="policy",
            reason=policy_message,
            action=action,
            params=parsed_params,
            source_ip=source_ip,
            target=target,
            chain_id=chain_id,
            trace_id=trace_id,
            risk_level=final_risk_level,
            risk_score=final_risk_score,
            steps=steps,
            triggered_rule=policy_result.triggered_rule,
            policy_trace=policy_trace,
            risk_assessment=risk_assessment,
        )

    if policy_result.action == Action.CONFIRM:
        from services.pending_queue import create_pending

        pending_id = create_pending(
            tool_name=action,
            params=parsed_params,
            rule_id=policy_result.triggered_rule,
            rule_name=policy_result.triggered_rule,
            severity=policy_result.severity,
            message=policy_message,
            source_ip=source_ip,
            action=action,
            chain_id=chain_id,
            ttl_seconds=300,
        )
        risk_assessment = get_risk_engine().score_runtime(
            action=action,
            target=target,
            decision="confirm",
            blocked_at="policy",
            input_score=risk_score,
            policy_trace=policy_trace,
            source_ip=source_ip,
            token=_token_id(token_meta),
            session=chain_id,
            chain_id=chain_id,
            actor=actor,
        )
        final_risk_score = max(policy_result.severity, risk_score, int(risk_assessment.get("risk_score") or 0))
        final_risk_level = risk_assessment.get("risk_level") or "medium"
        add_event(
            event_type="策略确认",
            detail=f"工具={action}, 规则={policy_result.triggered_rule}, pending_id={pending_id}",
            status="需确认",
            source_ip=source_ip,
            action=action,
            tool_name=action,
            target=target,
            rule_id=policy_result.triggered_rule,
            category="policy_confirmation",
            threat_level=final_risk_level,
            confidence=final_risk_score,
            chain_id=chain_id,
            stage="policy_confirm",
            metadata={
                "message": policy_message,
                "pending_id": pending_id,
                "confirm_url": f"/api/tool/pending/{pending_id}/confirm",
                "execute_url": f"/api/tool/pending/{pending_id}/execute",
                "trace_id": trace_id,
                "policy_trace": policy_trace,
            },
        )
        _add_runtime_conclusion(
            action=action,
            target=target,
            decision="confirm",
            reason=policy_message,
            source_ip=source_ip,
            chain_id=chain_id,
            trace_id=trace_id,
            risk_level=final_risk_level,
            risk_score=final_risk_score,
            steps=steps,
            blocked_at="policy",
            rule_id=policy_result.triggered_rule,
            extra={"pending_id": pending_id},
            policy_trace=policy_trace,
            risk_assessment=risk_assessment,
        )
        return _runtime_result(
            result="confirm",
            decision="confirm",
            blocked_at="policy",
            reason=policy_message,
            action=action,
            params=parsed_params,
            source_ip=source_ip,
            target=target,
            chain_id=chain_id,
            trace_id=trace_id,
            risk_level=final_risk_level,
            risk_score=final_risk_score,
            steps=steps,
            triggered_rule=policy_result.triggered_rule,
            pending_id=pending_id,
            confirm_url=f"/api/tool/pending/{pending_id}/confirm",
            execute_url=f"/api/tool/pending/{pending_id}/execute",
            policy_trace=policy_trace,
            risk_assessment=risk_assessment,
        )

    tool_params = json.dumps(parsed_params, ensure_ascii=False) if parsed_params else params_text
    tool_result = run_tool(
        action,
        tool_params,
        source_ip=source_ip,
        action=action,
        chain_id=chain_id,
        token_meta=token_meta,
    )
    tool_status = tool_result.get("status", "unknown")
    decision, blocked_at, step_status = _decision_from_tool_status(tool_status)
    product_result = _productize_tool_result(action, target, tool_result, decision, blocked_at)
    summary = product_result["summary"]
    audit = tool_result.get("audit") or {}
    severity = int(audit.get("severity") or _severity_from_status(tool_status))
    risk_assessment = get_risk_engine().score_runtime(
        action=action,
        target=target,
        decision=decision,
        blocked_at=blocked_at,
        input_score=risk_score,
        policy_trace=policy_trace,
        tool_result=tool_result,
        source_ip=source_ip,
        token=_token_id(token_meta),
        session=chain_id,
        chain_id=chain_id,
        actor=actor,
    )
    severity = max(severity, int(risk_assessment.get("risk_score") or 0))
    risk_level = risk_assessment.get("risk_level") or audit.get("threat_level") or ("high" if decision == "blocked" else "low")

    _add_step(
        steps,
        "tool_finished",
        "工具执行",
        step_status,
        summary,
        risk_score=severity,
        rule_id=audit.get("rule_id"),
    )
    _add_runtime_conclusion(
        action=action,
        target=target,
        decision=decision,
        reason=summary,
        source_ip=source_ip,
        chain_id=chain_id,
        trace_id=trace_id,
        risk_level=risk_level,
        risk_score=max(risk_score, severity),
        steps=steps,
        blocked_at=blocked_at,
        rule_id=audit.get("rule_id"),
        tool_evidence=product_result,
        policy_trace=policy_trace,
        risk_assessment=risk_assessment,
    )

    return _runtime_result(
        result=decision,
        decision=decision,
        blocked_at=blocked_at,
        reason=summary if decision != "allowed" else "",
        message=summary,
        action=action,
        params=parsed_params,
        source_ip=source_ip,
        target=target,
        chain_id=chain_id,
        trace_id=trace_id,
        risk_level=risk_level,
        risk_score=max(risk_score, severity),
        risk_assessment=risk_assessment,
        steps=steps,
        sandbox_mode=tool_result.get("mode", "mock"),
        tool_result=tool_result,
        tool_evidence=product_result,
        triggered_rule=audit.get("rule_id"),
        pending_id=tool_result.get("pending_id") or (tool_result.get("data") or {}).get("pending_id"),
        policy_trace=policy_trace,
    )


def _normalize_params(params: Any) -> Tuple[str, Dict[str, Any]]:
    if isinstance(params, dict):
        return json.dumps(params, ensure_ascii=False), params
    params_text = "" if params is None else str(params)
    try:
        parsed = json.loads(params_text)
        if isinstance(parsed, dict):
            return params_text, parsed
    except (TypeError, json.JSONDecodeError):
        pass

    parsed: Dict[str, Any] = {}
    for pair in re.split(r"[&;]\s*", params_text):
        if "=" in pair:
            key, value = pair.split("=", 1)
            parsed[key.strip()] = value.strip().strip("\"'")
    return params_text, parsed


def _build_detection_context(action: str, params_text: str, parsed_params: dict, user_input: str = "") -> str:
    if user_input:
        return str(user_input)
    intent_fields = " ".join(str(v) for v in parsed_params.values())
    return f"工具={action}；参数={params_text}；意图字段={intent_fields}"


def _safe_hybrid_detect(text: str, fast: bool = False):
    try:
        if fast:
            return _fast_rule_detect(text)
        return hybrid_detect(text)
    except Exception as exc:
        return False, f"检测引擎异常，已转入策略层复核：{exc}", {
            "combined": 35,
            "threat_level": "medium",
            "engine_error": str(exc),
        }


def _fast_rule_detect(text: str):
    rule_alert, rule_hit, rule_conf, rule_hits = rule_detect(text)
    score = int(round(float(rule_conf or 0)))
    if score >= 70:
        threat_level = "high"
    elif score >= 40:
        threat_level = "medium"
    elif score >= 15:
        threat_level = "low"
    else:
        threat_level = "none"
    effective_alert = bool(rule_alert) and score >= 40
    return effective_alert, (f"规则命中: {rule_hit}" if effective_alert else "未检测到明确威胁"), {
        "rule": {
            "alert": effective_alert,
            "confidence": score,
            "hit": rule_hit,
            "all_hits": rule_hits,
        },
        "semantic": {"alert": False, "confidence": 0, "engine": "fast_rule"},
        "combined": score,
        "threat_level": threat_level,
        "api_fallback": False,
        "cached": False,
    }


def _extract_target(action: str, parsed_params: dict, params_text: str) -> str:
    if action == "send_email":
        return parsed_params.get("to", "")
    if action in {"read_file", "write_file"}:
        return parsed_params.get("path") or parsed_params.get("file") or parsed_params.get("filename") or ""
    if action in {"http_request", "call_api"}:
        return parsed_params.get("url") or parsed_params.get("endpoint") or ""
    if action == "query_db":
        return (parsed_params.get("query") or parsed_params.get("sql") or params_text)[:120]
    return parsed_params.get("target") or params_text[:120]


def _token_id(token_meta: dict) -> str:
    if not isinstance(token_meta, dict):
        return None
    return token_meta.get("token_id") or token_meta.get("token_name") or token_meta.get("name")


def _confidence_score(confidence: Any) -> int:
    if isinstance(confidence, dict):
        return int(round(float(confidence.get("combined", 0) or 0)))
    return 0


def _threat_level(confidence: Any, default: str = "low") -> str:
    if isinstance(confidence, dict):
        return confidence.get("threat_level") or default
    return default


def _policy_message(policy_result) -> str:
    if policy_result.triggered_rule in POLICY_MESSAGES:
        return POLICY_MESSAGES[policy_result.triggered_rule]
    return policy_result.message or ""


def _decision_from_tool_status(status: str) -> Tuple[str, str, str]:
    if status in {"executed", "mock"}:
        return "allowed", "none", "passed"
    if status in {"blocked"}:
        return "blocked", "tool", "blocked"
    if status in {"pending"}:
        return "confirm", "tool", "confirm"
    if status == "timeout":
        return "timeout", "tool", "blocked"
    return "error", "tool", "error"


def _tool_summary(action: str, tool_result: dict, decision: str) -> str:
    return _productize_tool_result(action, "", tool_result, decision, "tool")["summary"]


def _productize_tool_result(action: str, target: str, tool_result: dict, decision: str, blocked_at: str) -> dict:
    audit = tool_result.get("audit") or {}
    data = tool_result.get("data") or {}
    reason = audit.get("reason") or tool_result.get("summary") or ""
    base = {
        "decision": decision,
        "blocked_at": blocked_at,
        "tool": action,
        "target": target or audit.get("target") or data.get("url") or data.get("filename") or data.get("to") or "",
        "reason": reason,
        "evidence": [],
        "recommendation": "",
        "summary": "",
    }

    if action in {"read_file", "write_file"}:
        base["evidence"] = [
            f"访问目标: {base['target'] or '-'}",
            f"沙箱路径: {audit.get('resolved_path') or '未进入文件系统'}",
            f"沙箱判定: {tool_result.get('summary') or '-'}",
        ]
        base["recommendation"] = "将文件访问限制在业务白名单目录内，敏感路径请求进入人工复核。"
    elif action == "send_email":
        recipients = data.get("recipients") or [base["target"]] if base.get("target") else []
        base["evidence"] = [
            f"收件目标: {', '.join(recipients) if isinstance(recipients, list) else recipients}",
            f"沙箱模式: {tool_result.get('mode') or '-'}",
            f"策略原因: {reason or '-'}",
        ]
        base["recommendation"] = "外发邮件必须经过收件人白名单、敏感内容检测和频率限制。"
    elif action in {"http_request", "call_api"}:
        base["evidence"] = [
            f"请求目标: {base['target'] or data.get('url') or '-'}",
            f"域名: {audit.get('host') or '-'}",
            f"响应策略: {tool_result.get('summary') or '-'}",
        ]
        base["recommendation"] = "外联请求应绑定域名白名单、SSRF 防护和响应体大小限制。"
    elif action == "query_db":
        base["evidence"] = [
            f"SQL 摘要: {(data.get('query') or base['target'] or '-')[:160]}",
            f"规则原因: {reason or '-'}",
            f"沙箱判定: {tool_result.get('summary') or '-'}",
        ]
        base["recommendation"] = "数据库查询需进行只读约束、敏感字段审计和高危写操作阻断。"
    else:
        base["evidence"] = [
            f"工具: {action}",
            f"目标: {base['target'] or '-'}",
            f"结果: {tool_result.get('summary') or '-'}",
        ]
        base["recommendation"] = "保持最小权限、参数审计和异常告警。"

    if decision == "allowed":
        base["summary"] = f"{action} 已通过策略和沙箱审计。"
    elif decision == "blocked":
        base["summary"] = f"{action} 已被阻断：{tool_result.get('summary') or reason or '命中安全策略'}"
    elif decision == "confirm":
        base["summary"] = f"{action} 需要确认：{tool_result.get('summary') or reason or '存在中风险操作'}"
    elif decision == "timeout":
        base["summary"] = f"{action} 执行超时，已进入异常处置。"
    else:
        base["summary"] = f"{action} 执行异常：{tool_result.get('summary') or reason or '未知错误'}"
    return base


def _severity_from_status(status: str) -> int:
    return {
        "blocked": 85,
        "timeout": 70,
        "error": 60,
        "pending": 55,
        "executed": 20,
        "mock": 10,
    }.get(status, 50)


def _add_step(steps: list, stage: str, title: str, status: str, detail: str, risk_score: int = 0, rule_id: str = None, evidence: dict = None):
    item = {
        "stage": stage,
        "title": title,
        "status": status,
        "detail": detail,
        "risk_score": int(risk_score or 0),
        "rule_id": rule_id,
    }
    if evidence:
        item["evidence"] = evidence
    steps.append(item)


def _runtime_result(**kwargs) -> dict:
    kwargs.setdefault("runtime_status", kwargs.get("decision"))
    decision = _normalize_runtime_status(kwargs.get("decision") or kwargs.get("result") or kwargs.get("runtime_status"))
    kwargs.setdefault("status_code", decision)
    kwargs.setdefault("runtime_conclusion", _runtime_conclusion(
        decision=decision,
        reason=kwargs.get("reason") or kwargs.get("message") or "",
        blocked_at=kwargs.get("blocked_at") or "unknown",
    ))
    kwargs.setdefault("context", "runtime_gateway")
    return kwargs


def _normalize_runtime_status(value: Any) -> str:
    text = str(value or "").lower()
    if text in {"block", "blocked", "deny", "rejected"}:
        return "blocked"
    if text in {"confirm", "review", "pending", "ask"}:
        return "confirm"
    if text in {"allow", "allowed", "pass", "passed", "executed", "mock"}:
        return "allowed"
    if text in {"timeout"}:
        return "timeout"
    if text in {"error", "failed", "failure"}:
        return "error"
    return text or "unknown"


def _runtime_conclusion(decision: str, reason: str = "", blocked_at: str = "unknown") -> str:
    if decision == "blocked":
        return f"已阻断，阻断阶段：{blocked_at}。{reason}".strip()
    if decision == "confirm":
        return f"需人工确认，触发阶段：{blocked_at}。{reason}".strip()
    if decision == "allowed":
        return "已放行，检测、策略与工具审计链路均已记录。"
    if decision in {"timeout", "error"}:
        return f"执行异常，异常阶段：{blocked_at}。{reason}".strip()
    return reason or "已完成运行时审计。"


def _add_runtime_conclusion(action: str, target: str, decision: str, reason: str, source_ip: str,
                            chain_id: str, trace_id: str, risk_level: str, risk_score: int,
                            steps: list, blocked_at: str, rule_id: str = None,
                            tool_evidence: dict = None, extra: dict = None, policy_trace: dict = None,
                            risk_assessment: dict = None):
    status = {
        "blocked": "已阻断",
        "confirm": "需确认",
        "allowed": "已放行",
        "timeout": "异常",
        "error": "异常",
    }.get(decision, "已评估")
    metadata = {
        "decision": decision,
        "runtime_status": decision,
        "blocked_at": blocked_at,
        "trace_id": trace_id,
        "steps": steps,
        "tool_evidence": tool_evidence,
        "policy_trace": policy_trace,
        "risk_assessment": risk_assessment,
    }
    if extra:
        metadata.update(extra)
    add_event(
        event_type="运行时结论",
        detail=reason,
        status=status,
        source_ip=source_ip,
        action=action,
        tool_name=action,
        target=target,
        rule_id=rule_id,
        category="runtime_conclusion",
        threat_level=risk_level,
        confidence=risk_score,
        chain_id=chain_id,
        stage="runtime_conclusion",
        metadata=metadata,
    )


def _preview(value: Any, limit: int = 300):
    text = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)
    return text[:limit]


def _broadcast_runtime_alert(event_type: str, action: str, status: str, threat_level: str, confidence: int, source_ip: str, target: str, chain_id: str, reason: str):
    broadcast_alert(
        event_type,
        f"工具={action}, 目标={target or '-'}",
        status,
        threat_level,
        confidence,
        source_ip=source_ip,
        action=action,
        tool_name=action,
        target=target,
        category="runtime_gateway",
        metadata={"reason": reason, "chain_id": chain_id},
    )
