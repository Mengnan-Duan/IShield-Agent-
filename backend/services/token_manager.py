"""Token lifecycle manager -- create, validate, revoke, rotate tokens"""
import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

REGISTRY_FILE = Path(__file__).parent.parent / "data" / "token_registry.json"
_LOCK = threading.RLock()
_UTC8 = timezone(timedelta(hours=8))
_VALID_ROLES = {"admin", "operator", "analyst", "readonly", "guest"}
DEFAULT_SCOPES_BY_ROLE = {
    "admin": ["*"],
    "operator": [
        "tool:detect", "tool:simulate", "tool:conversation", "tool:campaign", "tool:redteam",
        "tool:http_request", "tool:send_email", "tool:query_db", "tool:post_social", "tool:read_file",
    ],
    "analyst": ["tool:detect", "tool:simulate", "tool:conversation", "tool:read_file"],
    "readonly": ["tool:detect"],
    "guest": ["tool:detect"],
}
DEFAULT_ALLOWED_TOOLS_BY_ROLE = {
    "admin": ["*"],
    "operator": ["detect", "simulate", "conversation", "campaign", "redteam", "http_request", "send_email", "query_db", "post_social", "read_file"],
    "analyst": ["detect", "simulate", "conversation", "read_file"],
    "readonly": ["detect"],
    "guest": ["detect"],
}
DEFAULT_CONSTRAINTS_BY_ROLE = {
    "admin": {},
    "operator": {
        "http_request": {"domain_mode": "observe", "allow_unknown_domains": False},
        "write_file": {"sandbox_only": True},
        "query_db": {"allow_write": False},
    },
    "analyst": {
        "http_request": {"domain_mode": "challenge", "internal_only": True},
        "write_file": {"sandbox_only": True, "disabled": True},
        "query_db": {"allow_write": False},
    },
    "readonly": {
        "http_request": {"disabled": True},
        "write_file": {"disabled": True},
        "query_db": {"allow_write": False},
        "send_email": {"disabled": True},
        "post_social": {"disabled": True},
    },
    "guest": {
        "http_request": {"disabled": True},
        "write_file": {"disabled": True},
        "query_db": {"allow_write": False},
        "send_email": {"disabled": True},
        "post_social": {"disabled": True},
    },
}


def _utc_now():
    return datetime.now(_UTC8)


def _load_registry() -> dict:
    if REGISTRY_FILE.exists():
        try:
            with open(REGISTRY_FILE, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "tokens" in data:
                    return data
        except (json.JSONDecodeError, IOError):
            pass
    return {"tokens": {}, "approvals": {}}


def _save_registry(data: dict) -> None:
    with _LOCK:
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def _generate_key() -> str:
    return secrets.token_urlsafe(32)


def _normalize_role(role: str) -> str:
    role = (role or "operator").strip().lower()
    return role if role in _VALID_ROLES else "operator"


def _default_scopes_for_role(role: str) -> list[str]:
    return list(DEFAULT_SCOPES_BY_ROLE.get(role, DEFAULT_SCOPES_BY_ROLE["operator"]))


def _default_tools_for_role(role: str) -> list[str]:
    return list(DEFAULT_ALLOWED_TOOLS_BY_ROLE.get(role, DEFAULT_ALLOWED_TOOLS_BY_ROLE["operator"]))


def _default_constraints_for_role(role: str) -> dict:
    return dict(DEFAULT_CONSTRAINTS_BY_ROLE.get(role, {}))


def _hash_key(name: str, key: str) -> str:
    return hmac.new(name.encode("utf-8"), key.encode("utf-8"), hashlib.sha256).hexdigest()


def _build_token_meta(name: str, entry: dict) -> dict:
    role = _normalize_role(entry.get("role", "operator"))
    scopes = entry.get("scopes") or _default_scopes_for_role(role)
    allowed_tools = entry.get("allowed_tools") or _default_tools_for_role(role)
    constraints = entry.get("constraints") or _default_constraints_for_role(role)
    write_access = bool(entry.get("write_access", role not in {"readonly", "guest"}))
    return {
        "name": name,
        "subject": entry.get("subject") or name,
        "role": role,
        "readonly": not write_access,
        "write_access": write_access,
        "scopes": scopes,
        "allowed_tools": allowed_tools,
        "constraints": constraints,
        "allowed_ips": entry.get("allowed_ips", ["*"]),
        "status": "revoked" if entry.get("revoked") else "active",
        "issue_source": entry.get("issue_source", "registry"),
        "requires_approval": bool(entry.get("requires_approval", role == "admin")),
        "expires_at": entry.get("expires_at"),
        "last_used_at": entry.get("last_used_at"),
        "request_count": entry.get("request_count", 0),
    }


def create_token(
    name: str,
    role: str = "operator",
    description: str = "",
    expires_days: Optional[int] = None,
    allowed_ips: Optional[list] = None,
    scopes: Optional[list] = None,
    allowed_tools: Optional[list] = None,
    constraints: Optional[dict] = None,
    write_access: Optional[bool] = None,
    requires_approval: Optional[bool] = None,
) -> dict:
    data = _load_registry()
    if name in data["tokens"]:
        raise ValueError(f"Token '{name}' already exists")

    role = _normalize_role(role)
    key = _generate_key()
    key_hash = _hash_key(name, key)
    now = _utc_now()
    expires_at = None
    if expires_days:
        expires_at = (now + timedelta(days=expires_days)).isoformat()

    actual_write_access = bool(write_access) if write_access is not None else role not in {"readonly", "guest"}
    actual_scopes = scopes or _default_scopes_for_role(role)
    actual_tools = allowed_tools or _default_tools_for_role(role)
    actual_constraints = constraints or _default_constraints_for_role(role)
    actual_requires_approval = bool(requires_approval) if requires_approval is not None else role == "admin"

    data.setdefault("approvals", {})
    data["tokens"][name] = {
        "name": name,
        "subject": name,
        "role": role,
        "description": description,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        "last_used_at": None,
        "revoked": False,
        "revoked_at": None,
        "allowed_ips": allowed_ips or ["*"],
        "request_count": 0,
        "key_hash": key_hash,
        "scopes": actual_scopes,
        "allowed_tools": actual_tools,
        "constraints": actual_constraints,
        "write_access": actual_write_access,
        "requires_approval": actual_requires_approval,
        "issue_source": "registry",
    }
    _save_registry(data)

    return {
        "name": name,
        "key": f"{name}:{key}",
        "role": role,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        "allowed_ips": allowed_ips or ["*"],
        "scopes": actual_scopes,
        "allowed_tools": actual_tools,
        "constraints": actual_constraints,
        "write_access": actual_write_access,
        "requires_approval": actual_requires_approval,
        "warning": "This key is shown only once. Save it securely.",
    }


def revoke_token(name: str, reason: str = "") -> bool:
    data = _load_registry()
    if name not in data["tokens"]:
        return False
    data["tokens"][name]["revoked"] = True
    data["tokens"][name]["revoked_at"] = _utc_now().isoformat()
    data["tokens"][name]["revoke_reason"] = reason
    _save_registry(data)
    return True


def rotate_token(name: str) -> Optional[dict]:
    data = _load_registry()
    if name not in data["tokens"] or data["tokens"][name]["revoked"]:
        return None

    new_key = _generate_key()
    data["tokens"][name]["key_hash"] = _hash_key(name, new_key)
    data["tokens"][name]["last_rotated_at"] = _utc_now().isoformat()
    data["tokens"][name]["rotation_count"] = data["tokens"][name].get("rotation_count", 0) + 1
    _save_registry(data)
    return {"name": name, "key": f"{name}:{new_key}"}


def create_approval_code(name: str, action: str, ttl_seconds: int = 300) -> dict:
    data = _load_registry()
    code = secrets.token_hex(3).upper()
    now = _utc_now()
    data.setdefault("approvals", {})
    data["approvals"][f"{name}:{action}"] = {
        "code": code,
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "created_at": now.isoformat(),
    }
    _save_registry(data)
    return {"code": code, "expires_at": data["approvals"][f"{name}:{action}"]["expires_at"]}


def verify_approval_code(name: str, action: str, code: str) -> tuple[bool, str]:
    data = _load_registry()
    record = data.get("approvals", {}).get(f"{name}:{action}")
    if not record:
        return False, "approval code not found"
    try:
        expires_dt = datetime.fromisoformat(record["expires_at"])
        if expires_dt < _utc_now():
            return False, "approval code expired"
    except ValueError:
        return False, "approval code invalid"
    if (code or "").strip().upper() != (record.get("code") or "").strip().upper():
        return False, "approval code mismatch"
    data.get("approvals", {}).pop(f"{name}:{action}", None)
    _save_registry(data)
    return True, "approval code verified"


def get_token_meta(name: str) -> Optional[dict]:
    data = _load_registry()
    entry = data["tokens"].get(name)
    if not entry:
        return None
    return _build_token_meta(name, entry)


def validate_token(name: str, presented_token: str, ip: str) -> tuple[bool, str, Optional[dict]]:
    if not name:
        return False, "missing token name", None

    data = _load_registry()
    token_entry = data["tokens"].get(name)
    if not token_entry:
        return False, "token not found", None

    if token_entry.get("revoked"):
        return False, f"token revoked at {token_entry.get('revoked_at', 'unknown')}", None

    expires = token_entry.get("expires_at")
    if expires:
        try:
            expires_dt = datetime.fromisoformat(expires).replace(tzinfo=_UTC8)
            if expires_dt < _utc_now():
                return False, f"token expired at {expires}", None
        except ValueError:
            pass

    allowed_ips = token_entry.get("allowed_ips", ["*"])
    if "*" not in allowed_ips and ip not in allowed_ips:
        return False, f"IP {ip} not in token whitelist", None

    if presented_token:
        if ":" not in presented_token:
            return False, "token format invalid", None
        _, raw_key = presented_token.split(":", 1)
        expected = token_entry.get("key_hash")
        if expected:
            if not hmac.compare_digest(expected, _hash_key(name, raw_key)):
                return False, "token signature mismatch", None

    data["tokens"][name]["last_used_at"] = _utc_now().isoformat()
    data["tokens"][name]["request_count"] = data["tokens"][name].get("request_count", 0) + 1
    _save_registry(data)

    return True, f"valid (role={token_entry.get('role')})", _build_token_meta(name, data["tokens"][name])


def list_tokens() -> list:
    data = _load_registry()
    results = []
    for v in data["tokens"].values():
        status = "revoked" if v.get("revoked") else \
                 "expired" if (v.get("expires_at") and
                              (datetime.fromisoformat(v["expires_at"]).replace(tzinfo=_UTC8) < _utc_now()
                               if v["expires_at"] else False)) else "active"
        meta = _build_token_meta(v["name"], v)
        results.append({
            "name": v["name"],
            "role": meta["role"],
            "description": v.get("description", ""),
            "created_at": v["created_at"],
            "expires_at": v.get("expires_at"),
            "last_used_at": v.get("last_used_at"),
            "revoked": v.get("revoked", False),
            "allowed_ips": v.get("allowed_ips", ["*"]),
            "request_count": v.get("request_count", 0),
            "status": status,
            "scopes": meta["scopes"],
            "allowed_tools": meta["allowed_tools"],
            "constraints": meta["constraints"],
            "write_access": meta["write_access"],
            "requires_approval": meta["requires_approval"],
        })
    return results
