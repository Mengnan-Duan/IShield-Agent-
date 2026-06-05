"""统一工具执行器 — 超时控制 + 审计记录"""
import sys, os, json, time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.events import add_event
from services.websocket import broadcast_event, broadcast_alert

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
    audit_context = {
        "source_ip": source_ip,
        "action": action,
        "tool_name": tool_name,
        "target": _extract_target(tool_name, parsed_params),
        "category": "tool_execution",
        "metadata": {"params": parsed_params},
    }

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
            metadata=audit,
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
        filename=params.get("file") or params.get("filename") or params.get("path", "untitled.txt"),
        content=params.get("content") or params.get("body") or params.get("text", ""),
        append=bool(params.get("append", False)),
        overwrite=bool(params.get("overwrite", False)),
        source_ip=kwargs.get("source_ip"),
    )


def _handle_http(params: dict, **kwargs) -> dict:
    from .sandbox_http import get_sandbox
    sandbox = get_sandbox()
    method = params.get("method", "GET").upper()
    url = params.get("url") or params.get("endpoint") or params.get("href", "")
    body = params.get("body") or params.get("data")
    return sandbox.request(method, url, json=body if body else None, source_ip=kwargs.get("source_ip"))


register_tool("send_email")(lambda p, **k: _handle_email(p, **k))
register_tool("read_file")(lambda p, **k: _handle_file_read(p, **k))
register_tool("write_file")(lambda p, **k: _handle_file_write(p, **k))
register_tool("http_request")(lambda p, **k: _handle_http(p, **k))
register_tool("query_db")(lambda p, **k: {
    "status": "mock",
    "tool": "query_db",
    "mode": "mock",
    "summary": "query_db 当前仍为演示模式",
    "audit": {"reason": "database_not_configured"},
    "data": {"message": "query_db 需要连接真实数据库，请在 config.py 中配置数据库连接"},
})
register_tool("post_social")(lambda p, **k: {
    "status": "mock",
    "tool": "post_social",
    "mode": "mock",
    "summary": "post_social 在沙箱模式下被禁用",
    "audit": {"reason": "sandbox_disabled"},
    "data": {"message": "post_social 在沙箱模式下被禁用"},
})
