"""Token lifecycle manager -- create, validate, revoke, rotate tokens"""
import json
import os
import secrets
import time
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

REGISTRY_FILE = Path(__file__).parent.parent / "data" / "token_registry.json"
_lock = threading.RLock()
_utc8 = timezone(timedelta(hours=8))


def _utc_now():
    return datetime.now(_utc8)


def _load_registry() -> dict:
    if REGISTRY_FILE.exists():
        try:
            with open(REGISTRY_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {"tokens": {}}


def _save_registry(data: dict) -> None:
    with _lock:
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def _generate_key() -> str:
    return secrets.token_urlsafe(32)


def create_token(
    name: str,
    role: str = "operator",
    description: str = "",
    expires_days: Optional[int] = None,
    allowed_ips: Optional[list] = None,
) -> dict:
    data = _load_registry()
    if name in data["tokens"]:
        raise ValueError(f"Token '{name}' already exists")

    key = _generate_key()
    now = _utc_now()
    expires_at = None
    if expires_days:
        expires_at = (now + timedelta(days=expires_days)).isoformat()

    data["tokens"][name] = {
        "name": name,
        "role": role,
        "description": description,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        "last_used_at": None,
        "revoked": False,
        "revoked_at": None,
        "allowed_ips": allowed_ips or ["*"],
        "request_count": 0,
    }
    _save_registry(data)

    return {
        "name": name,
        "key": key,
        "role": role,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        "allowed_ips": allowed_ips or ["*"],
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
    data["tokens"][name]["last_rotated_at"] = _utc_now().isoformat()
    data["tokens"][name]["rotation_count"] = data["tokens"][name].get("rotation_count", 0) + 1
    _save_registry(data)
    return {"name": name, "key": new_key}


def validate_token(name: str, key: str, ip: str) -> tuple[bool, str]:
    if not name:
        return False, "missing token name"

    data = _load_registry()
    token_entry = data["tokens"].get(name)
    if not token_entry:
        return False, "token not found"

    if token_entry.get("revoked"):
        return False, f"token revoked at {token_entry.get('revoked_at', 'unknown')}"

    expires = token_entry.get("expires_at")
    if expires:
        try:
            expires_dt = datetime.fromisoformat(expires).replace(tzinfo=_utc8)
            if expires_dt < _utc_now():
                return False, f"token expired at {expires}"
        except ValueError:
            pass

    allowed_ips = token_entry.get("allowed_ips", ["*"])
    if "*" not in allowed_ips and ip not in allowed_ips:
        return False, f"IP {ip} not in token whitelist"

    data["tokens"][name]["last_used_at"] = _utc_now().isoformat()
    data["tokens"][name]["request_count"] = data["tokens"][name].get("request_count", 0) + 1
    _save_registry(data)

    return True, f"valid (role={token_entry.get('role')})"


def list_tokens() -> list:
    data = _load_registry()
    results = []
    for v in data["tokens"].values():
        status = "revoked" if v.get("revoked") else \
                 "expired" if (v.get("expires_at") and
                              (datetime.fromisoformat(v["expires_at"]).replace(tzinfo=_utc8) < _utc_now()
                               if v["expires_at"] else False)) else "active"
        results.append({
            "name": v["name"],
            "role": v["role"],
            "description": v.get("description", ""),
            "created_at": v["created_at"],
            "expires_at": v.get("expires_at"),
            "last_used_at": v.get("last_used_at"),
            "revoked": v.get("revoked", False),
            "allowed_ips": v.get("allowed_ips", ["*"]),
            "request_count": v.get("request_count", 0),
            "status": status,
        })
    return results
