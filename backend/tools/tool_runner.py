"""统一工具执行器 — 超时控制 + 事件记录"""
import sys, os, json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.events import add_event
from services.websocket import broadcast_event

TOOL_TIMEOUT = 10  # 秒


_TOOL_HANDLERS = {}


def register_tool(name: str):
    """装饰器：注册工具处理器"""
    def decorator(func):
        _TOOL_HANDLERS[name] = func
        return func
    return decorator


def run_tool(tool_name: str, params: str, **kwargs) -> dict:
    """
    统一工具执行入口。

    参数:
        tool_name: 工具名 (send_email / query_db / post_social / read_file / write_file / http_request)
        params:    参数字符串（格式: key=value&key2=value2 或 JSON 字符串）
        **kwargs: 额外参数

    返回:
        {"status": "executed"|"blocked"|"error"|"timeout", "result": dict}
    """
    # 解析参数
    parsed_params = _parse_params(params)

    # 查找处理器
    handler = _TOOL_HANDLERS.get(tool_name)
    if not handler:
        return {"status": "error", "message": f"未知工具: {tool_name}"}

    # 记录开始事件
    add_event(
        event_type=f"工具执行:{tool_name}",
        detail=f"工具={tool_name}, 参数={str(parsed_params)[:100]}",
        status="执行中",
    )

    # 带超时执行
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(handler, parsed_params, **kwargs)
            result = future.result(timeout=TOOL_TIMEOUT)
            result["_meta"] = {"tool": tool_name, "timeout": TOOL_TIMEOUT, "status": "executed"}
            add_event(
                event_type=f"工具完成:{tool_name}",
                detail=f"工具={tool_name}, 结果={str(result.get('status','unknown'))[:50]}",
                status="已完成",
            )
            broadcast_event("tool_executed", {"tool": tool_name, "result": result})
            return result
    except FuturesTimeoutError:
        add_event(
            event_type=f"工具超时:{tool_name}",
            detail=f"工具={tool_name} 执行超时({TOOL_TIMEOUT}秒)",
            status="已超时",
        )
        return {"status": "timeout", "message": f"执行超时({TOOL_TIMEOUT}秒)", "tool": tool_name}
    except Exception as e:
        add_event(
            event_type=f"工具错误:{tool_name}",
            detail=f"工具={tool_name}, 错误={str(e)[:100]}",
            status="已出错",
        )
        return {"status": "error", "message": str(e), "tool": tool_name}


def _parse_params(params_str: str) -> dict:
    """解析参数字符串为字典"""
    if not params_str:
        return {}
    # 尝试JSON解析
    try:
        return json.loads(params_str)
    except (json.JSONDecodeError, TypeError):
        pass
    # 尝试 key=value&key2=value2 格式
    result = {}
    for pair in params_str.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


# ── 内置工具处理器注册 ──────────────────────────────────────────────────────

def _handle_email(params: dict, **kwargs) -> dict:
    from .sandbox_email import get_sandbox
    sandbox = get_sandbox()
    return sandbox.send(
        to=params.get("to", ""),
        subject=params.get("subject", ""),
        body=params.get("body", params.get("content", "")),
        cc=params.get("cc"),
    )

def _handle_file_read(params: dict, **kwargs) -> dict:
    from .sandbox_file import get_sandbox
    sandbox = get_sandbox()
    return sandbox.read(params.get("file") or params.get("filename") or params.get("path", ""))

def _handle_file_write(params: dict, **kwargs) -> dict:
    from .sandbox_file import get_sandbox
    sandbox = get_sandbox()
    return sandbox.write(
        filename=params.get("file") or params.get("filename") or params.get("path", "untitled.txt"),
        content=params.get("content") or params.get("body") or params.get("text", ""),
    )

def _handle_http(params: dict, **kwargs) -> dict:
    from .sandbox_http import get_sandbox
    sandbox = get_sandbox()
    method = params.get("method", "GET").upper()
    url = params.get("url") or params.get("endpoint") or params.get("href", "")
    body = params.get("body") or params.get("data")
    return sandbox.request(method, url, json=body if body else None)

# 注册
register_tool("send_email")(lambda p, **k: _handle_email(p, **k))
register_tool("read_file")(lambda p, **k: _handle_file_read(p, **k))
register_tool("write_file")(lambda p, **k: _handle_file_write(p, **k))
register_tool("http_request")(lambda p, **k: _handle_http(p, **k))
register_tool("query_db")(lambda p, **k: {
    "status": "mock",
    "message": "query_db 需要连接真实数据库，请在 config.py 中配置数据库连接",
    "tool": "query_db"
})
register_tool("post_social")(lambda p, **k: {
    "status": "mock",
    "message": "post_social 在沙箱模式下被禁用",
    "tool": "post_social"
})
