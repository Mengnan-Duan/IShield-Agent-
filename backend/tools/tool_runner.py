"""统一工具执行器 — 超时控制 + 审计记录"""
import sys, os, json, time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.events import add_event
from services.websocket import broadcast_event, broadcast_alert
from services.supply_chain_guard import get_supply_chain_guard
from services.risk_engine import get_risk_engine
from services.tool_permissions import evaluate_tool_constraints

TOOL_TIMEOUT = 10
_TOOL_HANDLERS = {}


def register_tool(name: str):
    def decorator(func):
        _TOOL_HANDLERS[name] = func
        return func
    return decorator


def run_tool(tool_name: str, params: str, **kwargs) -> dict:
    parsed_params = _parse_params(params)
    handler = _TOOL_HANDLERS.get(tool_name)
    if not handler:
        return _finalize_result(tool_name, {
            "status": "error",
            "mode": "mock",
            "summary": f"未知工具: {tool_name}",
            "audit": {"reason": "unknown_tool", "params_preview": str(parsed_params)[:120]},
            "data": {},
        })

    source_ip = kwargs.get("source_ip")
    action = kwargs.get("action") or tool_name
    chain_id = kwargs.get("chain_id")
    token_meta = kwargs.get("token_meta") or {}
    audit_context = {
        "source_ip": source_ip,
        "action": action,
        "tool_name": tool_name,
        "target": _extract_target(tool_name, parsed_params),
        "category": "tool_execution",
        "metadata": {"params": parsed_params},
        "chain_id": chain_id,
    }

    perm_ok, perm_reason = evaluate_tool_constraints(token_meta, tool_name, parsed_params)
    if not perm_ok:
        blocked = _finalize_result(tool_name, {
            "status": "blocked",
            "mode": "mock",
            "summary": f"工具 {tool_name} 被身份权限策略阻断",
            "audit": {
                "reason": perm_reason,
                "rule_id": "IDENTITY-SCOPE-001",
                "severity": 86,
                "threat_level": "high",
            },
            "data": {"params": parsed_params},
        })
        _record_tool_result(blocked, audit_context)
        return blocked

    supply_result = _precheck_supply_chain(tool_name, parsed_params, chain_id)
    if supply_result:
        _record_tool_result(supply_result, audit_context)
        return supply_result

    add_event(
        event_type=f"工具执行:{tool_name}",
        detail=f"工具={tool_name}, 参数={str(parsed_params)[:100]}",
        status="执行中",
        source_ip=source_ip,
        action=action,
        tool_name=tool_name,
        target=audit_context["target"],
        category="tool_execution",
        metadata={"stage": "started", "params": parsed_params},
        chain_id=chain_id,
        stage="tool_started",
    )

    started_at = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(handler, parsed_params, **kwargs)
            raw_result = future.result(timeout=TOOL_TIMEOUT)
        elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)
        result = _finalize_result(tool_name, raw_result, elapsed_ms=elapsed_ms, timeout=TOOL_TIMEOUT)
        _record_tool_result(result, audit_context)
        return result
    except FuturesTimeoutError:
        result = _finalize_result(tool_name, {
            "status": "timeout",
            "mode": "real",
            "summary": f"工具 {tool_name} 执行超时",
            "audit": {"reason": f"执行超时({TOOL_TIMEOUT}秒)"},
            "data": {},
        }, elapsed_ms=round((time.perf_counter() - started_at) * 1000, 2), timeout=TOOL_TIMEOUT)
        _record_tool_result(result, audit_context)
        return result
    except Exception as e:
        result = _finalize_result(tool_name, {
            "status": "error",
            "mode": "real",
            "summary": f"工具 {tool_name} 执行失败",
            "audit": {"reason": str(e)},
            "data": {},
        }, elapsed_ms=round((time.perf_counter() - started_at) * 1000, 2), timeout=TOOL_TIMEOUT)
        _record_tool_result(result, audit_context)
        return result


def _record_tool_result(result: dict, audit_context: dict):
    status = result.get("status", "unknown")
    tool_name = result.get("tool")
    audit = result.get("audit", {})
    severity = audit.get("severity") or _severity_from_status(status)
    event_type = f"工具结果:{tool_name}"
    event_status = {
        "executed": "已放行",
        "blocked": "已阻断",
        "timeout": "已超时",
        "mock": "模拟执行",
        "error": "已出错",
    }.get(status, "未知")
    detail = f"工具={tool_name}, 状态={status}, 目标={audit_context.get('target') or '-'}"

    add_event(
        event_type=event_type,
        detail=detail,
        status=event_status,
        source_ip=audit_context.get("source_ip"),
        action=audit_context.get("action"),
        tool_name=tool_name,
        target=audit_context.get("target"),
        rule_id=audit.get("rule_id"),
        threat_level=audit.get("threat_level"),
        confidence=severity,
        category=audit_context.get("category"),
        metadata={
            "summary": result.get("summary"),
            "audit": audit,
            "mode": result.get("mode"),
            "data": result.get("data"),
            **(audit_context.get("metadata") or {}),
        },
        chain_id=audit_context.get("chain_id"),
        stage="tool_finished",
    )

    broadcast_event("tool_executed", result)
    if status in {"blocked", "error", "timeout"}:
        broadcast_alert(
            event_type=event_type,
            detail=detail,
            status=event_status,
            threat_level=audit.get("threat_level", "high" if status == "blocked" else "medium"),
            confidence=severity,
            source_ip=audit_context.get("source_ip"),
            action=audit_context.get("action"),
            tool_name=tool_name,
            target=audit_context.get("target"),
            rule_id=audit.get("rule_id"),
            category=audit_context.get("category"),
            metadata={**audit, "chain_id": audit_context.get("chain_id")},
        )


def _finalize_result(tool_name: str, raw_result: Any, elapsed_ms: float = None, timeout: int = TOOL_TIMEOUT) -> dict:
    result = raw_result if isinstance(raw_result, dict) else {"status": "error", "data": {"raw": raw_result}}
    normalized = {
        "status": result.get("status", "error"),
        "tool": result.get("tool", tool_name),
        "mode": result.get("mode", "real"),
        "summary": result.get("summary") or result.get("message") or f"工具 {tool_name} 已执行",
        "audit": dict(result.get("audit") or {}),
        "data": result.get("data") if "data" in result else _legacy_data(result),
    }
    normalized["audit"].setdefault("elapsed_ms", elapsed_ms)
    normalized["audit"].setdefault("timeout", timeout)
    return normalized


def _legacy_data(result: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in result.items() if k not in {"status", "mode", "summary", "message", "audit", "tool"}}


def _parse_params(params_str: str) -> dict:
    if not params_str:
        return {}
    try:
        return json.loads(params_str)
    except (json.JSONDecodeError, TypeError):
        pass
    result = {}
    for pair in params_str.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def _extract_target(tool_name: str, params: dict) -> str:
    if tool_name == "send_email":
        return params.get("to", "")
    if tool_name in {"read_file", "write_file"}:
        return params.get("file") or params.get("filename") or params.get("path", "")
    if tool_name == "http_request":
        return params.get("url") or params.get("endpoint") or ""
    return params.get("target") or ""


def _severity_from_status(status: str) -> int:
    return {
        "blocked": 85,
        "timeout": 70,
        "error": 60,
        "executed": 20,
        "mock": 10,
    }.get(status, 50)


def _precheck_supply_chain(tool_name: str, params: dict, chain_id: str = None) -> dict | None:
    if tool_name != "http_request":
        return None
    url = (params.get("url") or params.get("endpoint") or "").strip()
    if not url:
        return None
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    guard = get_supply_chain_guard()
    report = guard.record_request(domain=domain, method=params.get("method", "GET"), path=path, status_code=0, response_bytes=0, chain_id=chain_id)
    alerts = report.get("alerts", [])
    risk_score = report.get("risk_score", 0)
    action = "allow"
    if risk_score >= 60:
        action = "block"
    elif risk_score >= 30:
        action = "confirm"

    intent_text = f"{url} {(params.get('data') or '')} {(params.get('headers') or '')}".lower()
    suspicious_terms = ["token", "secret", "export", "db", "email", "password", "credential"]
    if sum(1 for t in suspicious_terms if t in intent_text) >= 2:
        risk_score += 25
        action = "block" if risk_score >= 60 else "confirm"
        alerts.append({"type": "data_egress_intent", "score": 25})

    if action == "block":
        get_risk_engine().record(score=40, reason=f"supply_chain_block:{domain}", source="tool_runner")
        return _finalize_result(tool_name, {
            "status": "blocked",
            "mode": "mock",
            "summary": f"供应链守卫阻断了对可疑域名 {domain} 的访问",
            "audit": {
                "reason": "suspicious_supply_chain_target",
                "rule_id": "SUPPLY-CHAIN-001",
                "severity": min(95, max(70, risk_score)),
                "threat_level": "high",
                "alerts": alerts,
            },
            "data": {"domain": domain, "path": path, "risk_score": risk_score},
        })
    if action == "confirm":
        return _finalize_result(tool_name, {
            "status": "blocked",
            "mode": "mock",
            "summary": f"供应链守卫要求确认后才能访问域名 {domain}",
            "audit": {
                "reason": "suspicious_supply_chain_target_confirm",
                "rule_id": "SUPPLY-CHAIN-CHALLENGE-001",
                "severity": min(88, max(45, risk_score)),
                "threat_level": "medium",
                "alerts": alerts,
            },
            "data": {"domain": domain, "path": path, "risk_score": risk_score},
        })
    return None


# ── 内置工具处理器注册 ──────────────────────────────────────────────────────
def _handle_email(params: dict, **kwargs) -> dict:
    from .sandbox_email import get_sandbox
    sandbox = get_sandbox()
    return sandbox.send(
        to=params.get("to", ""),
        subject=params.get("subject", ""),
        body=params.get("body", params.get("content", "")),
        cc=params.get("cc"),
        source_ip=kwargs.get("source_ip"),
    )


def _handle_file_read(params: dict, **kwargs) -> dict:
    from .sandbox_file import get_sandbox
    sandbox = get_sandbox()
    return sandbox.read(
        params.get("file") or params.get("filename") or params.get("path", ""),
        source_ip=kwargs.get("source_ip"),
    )


def _handle_file_write(params: dict, **kwargs) -> dict:
    from .sandbox_file import get_sandbox
    sandbox = get_sandbox()
    return sandbox.write(
        params.get("file") or params.get("filename") or params.get("path", ""),
        params.get("content", ""),
        source_ip=kwargs.get("source_ip"),
    )


def _handle_http(params: dict, **kwargs) -> dict:
    from .sandbox_http import get_sandbox
    sandbox = get_sandbox()
    return sandbox.request(
        url=params.get("url") or params.get("endpoint") or "",
        method=params.get("method", "GET"),
        data=params.get("data"),
        headers=params.get("headers"),
        source_ip=kwargs.get("source_ip"),
    )


def _handle_query_db(params: dict, **kwargs) -> dict:
    query = params.get("query") or params.get("sql") or ""
    query_lower = query.lower()
    blocked_keywords = ["drop ", "truncate ", "delete from", "update "]
    if any(kw in query_lower for kw in blocked_keywords):
        return {
            "status": "blocked",
            "tool": "query_db",
            "mode": "mock",
            "summary": "数据库沙箱阻止了危险写操作",
            "audit": {
                "reason": "dangerous_sql",
                "rule_id": "DB-SANDBOX-001",
                "severity": 92,
                "threat_level": "high",
            },
            "data": {"query": query[:200]},
        }
    return {
        "status": "mock",
        "tool": "query_db",
        "mode": "mock",
        "summary": "数据库查询已在沙箱中模拟执行",
        "audit": {"severity": 18, "threat_level": "low"},
        "data": {
            "query": query[:200],
            "rows": [
                {"id": 1, "name": "demo_user", "role": "analyst"},
                {"id": 2, "name": "sandbox_bot", "role": "service"},
            ],
        },
    }


def _handle_post_social(params: dict, **kwargs) -> dict:
    content = params.get("content", "")
    if any(k in content.lower() for k in ["api_key", "password", "secret", "token"]):
        return {
            "status": "blocked",
            "tool": "post_social",
            "mode": "mock",
            "summary": "社交平台沙箱阻止了敏感信息外发",
            "audit": {
                "reason": "sensitive_content",
                "rule_id": "SOCIAL-SANDBOX-001",
                "severity": 88,
                "threat_level": "high",
            },
            "data": {"content_preview": content[:120]},
        }
    return {
        "status": "mock",
        "tool": "post_social",
        "mode": "mock",
        "summary": "社交平台发布已在沙箱中模拟执行",
        "audit": {"severity": 12, "threat_level": "low"},
        "data": {"content_preview": content[:120]},
    }


register_tool("send_email")(_handle_email)
register_tool("read_file")(_handle_file_read)
register_tool("write_file")(_handle_file_write)
register_tool("http_request")(_handle_http)
register_tool("query_db")(_handle_query_db)
register_tool("post_social")(_handle_post_social)
