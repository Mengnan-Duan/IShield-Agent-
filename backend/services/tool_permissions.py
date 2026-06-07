"""工具权限服务 — 基于角色的工具访问控制（RBAC）"""
import json
import os
from typing import Tuple

PERMISSIONS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "tool_permissions.json"
)


def _load_permissions() -> dict:
    try:
        with open(PERMISSIONS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"roles": {}, "tools": {}}


def check_permission(token_name: str, tool: str) -> Tuple[bool, str]:
    """
    检查 token_name 是否有权限使用 tool。

    返回: (allowed: bool, reason: str)
    """
    data = _load_permissions()
    roles = data.get("roles", {})

    # 查找 token 对应的角色
    role = _token_role(token_name)
    if not role:
        return False, f"Token '{token_name}' has no assigned role"

    role_def = roles.get(role, {})
    tools = role_def.get("tools", [])

    if "*" in tools:
        return True, "admin: full access"

    if tool in tools:
        return True, f"role '{role}' allows '{tool}'"

    return False, f"role '{role}' does not allow '{tool}' (allowed: {', '.join(tools) or 'none'})"


def _token_role(token_name: str) -> str | None:
    """根据 token 名称推断角色"""
    name_lower = token_name.lower()
    if "admin" in name_lower:
        return "admin"
    if "operator" in name_lower:
        return "operator"
    if "analyst" in name_lower:
        return "analyst"
    if "readonly" in name_lower or "read" in name_lower:
        return "readonly"
    return "operator"  # 默认角色


def get_permissions_for_token(token_name: str) -> dict:
    """返回 token 的完整权限信息"""
    data = _load_permissions()
    role = _token_role(token_name)
    role_def = data.get("roles", {}).get(role, {})
    return {
        "token": token_name,
        "role": role,
        "description": role_def.get("description", ""),
        "tools": role_def.get("tools", []),
    }
