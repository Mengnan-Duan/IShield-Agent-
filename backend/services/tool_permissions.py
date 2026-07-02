"""工具权限服务 — 基于角色 + scope + 参数约束的工具访问控制"""
import json
from typing import Tuple

from runtime_paths import backend_data_dir

PERMISSIONS_FILE = backend_data_dir() / "tool_permissions.json"


TOOL_SCOPE_ALIASES = {
    "detect": "tool:detect",
    "simulate": "tool:simulate",
    "conversation": "tool:conversation",
    "campaign": "tool:campaign",
    "redteam": "tool:redteam",
    "http_request": "tool:http_request",
    "call_api": "tool:http_request",
    "write_file": "tool:write_file",
    "read_file": "tool:read_file",
    "query_db": "tool:query_db",
    "send_email": "tool:send_email",
    "post_social": "tool:post_social",
}


def _load_permissions() -> dict:
    try:
        with open(PERMISSIONS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"roles": {}, "tools": {}}


def _scope_for_tool(tool: str) -> str:
    return TOOL_SCOPE_ALIASES.get(tool, f"tool:{tool}")


def check_permission(token_meta: dict, tool: str) -> Tuple[bool, str]:
    """检查 token_meta 是否有权限使用 tool。"""
    data = _load_permissions()
    roles = data.get("roles", {})

    role = (token_meta or {}).get("role", "guest")
    role_def = roles.get(role, {})
    role_tools = role_def.get("tools", [])
    meta_tools = (token_meta or {}).get("allowed_tools", [])
    scopes = set((token_meta or {}).get("scopes", []) or [])
    required_scope = _scope_for_tool(tool)

    if "*" in meta_tools or "*" in role_tools or "*" in scopes:
        return True, "full access"

    if tool in meta_tools or tool in role_tools:
        return True, f"tool '{tool}' explicitly allowed"

    if required_scope in scopes:
        return True, f"scope '{required_scope}' allowed"

    return False, f"role '{role}' lacks tool '{tool}' and scope '{required_scope}'"


def evaluate_tool_constraints(token_meta: dict, tool: str, params: dict) -> Tuple[bool, str]:
    constraints = ((token_meta or {}).get("constraints") or {}).get(tool, {})
    if not constraints:
        return True, "no constraints"

    if constraints.get("disabled"):
        return False, f"tool '{tool}' disabled by token constraints"

    if tool in {"http_request", "call_api"}:
        url = (params.get("url") or params.get("endpoint") or "").lower()
        if constraints.get("internal_only") and not any(s in url for s in ("localhost", "127.0.0.1", "/api/")):
            return False, "http_request limited to internal targets"

    if tool == "write_file":
        path = (params.get("file") or params.get("filename") or params.get("path") or "").lower()
        if constraints.get("sandbox_only") and not any(s in path for s in ("sandbox", "tmp", "temp", "uploads")):
            return False, "write_file limited to sandbox paths"

    if tool == "query_db":
        query = (params.get("query") or params.get("sql") or "").lower()
        if not constraints.get("allow_write", False) and any(k in query for k in ("update ", "delete ", "insert ", "drop ", "truncate ")):
            return False, "query_db write operations forbidden"

    return True, "constraints passed"


def get_permissions_for_token(token_meta: dict) -> dict:
    """返回 token 的完整权限信息"""
    data = _load_permissions()
    role = (token_meta or {}).get("role", "guest")
    role_def = data.get("roles", {}).get(role, {})
    return {
        "token": (token_meta or {}).get("name", "unknown"),
        "role": role,
        "description": role_def.get("description", ""),
        "tools": (token_meta or {}).get("allowed_tools", []) or role_def.get("tools", []),
        "scopes": (token_meta or {}).get("scopes", []),
        "constraints": (token_meta or {}).get("constraints", {}),
        "write_access": (token_meta or {}).get("write_access", False),
    }
