"""Unified API response helpers for IShield."""
from datetime import datetime, timezone
import uuid

from flask import g, jsonify


class Err:
    OK = ("OK", 200)
    BAD_REQUEST = ("BAD_REQUEST", 400)
    VALIDATION_ERR = ("VALIDATION_ERR", 400)
    UNAUTHORIZED = ("UNAUTHORIZED", 401)
    FORBIDDEN = ("FORBIDDEN", 403)
    NOT_FOUND = ("NOT_FOUND", 404)
    RATE_LIMITED = ("RATE_LIMITED", 429)
    INTERNAL_ERR = ("INTERNAL_ERR", 500)
    SERVICE_UNAVAIL = ("SERVICE_UNAVAIL", 503)


def _trace_id(request_id=None):
    return request_id or getattr(g, "request_id", None) or str(uuid.uuid4())[:16]


def _chain_id_from(data=None, chain_id=None):
    if chain_id:
        return chain_id
    if isinstance(data, dict):
        if data.get("chain_id"):
            return data.get("chain_id")
        nested = data.get("chain")
        if isinstance(nested, dict) and nested.get("chain_id"):
            return nested.get("chain_id")
    return getattr(g, "chain_id", None)


def make_response(data=None, code="OK", message=None, request_id=None, chain_id=None):
    """Return a v4.0-compatible success payload.

    Existing clients can continue to read success/code/message/data. New clients
    can rely on trace_id, chain_id and error for deterministic UI handling.
    """
    trace_id = _trace_id(request_id)
    resolved_chain_id = _chain_id_from(data, chain_id)
    body = {
        "success": True,
        "code": code,
        "message": message,
        "trace_id": trace_id,
        "request_id": trace_id,
        "chain_id": resolved_chain_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
        "error": None,
    }
    return jsonify(body), 200


def make_error(error: tuple, message: str, request_id: str = None, details: dict = None, chain_id: str = None, recoverable: bool = False):
    """Return a v4.0-compatible error payload."""
    code, status = error
    trace_id = _trace_id(request_id)
    resolved_chain_id = _chain_id_from(details, chain_id)
    body = {
        "success": False,
        "code": code,
        "message": message,
        "trace_id": trace_id,
        "request_id": trace_id,
        "chain_id": resolved_chain_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": None,
        "error": {
            "code": code,
            "message": message,
            "detail": details or {},
            "recoverable": recoverable,
        },
    }
    if details:
        body["details"] = details
    return jsonify(body), status


def get_request_id():
    return str(uuid.uuid4())[:16]
