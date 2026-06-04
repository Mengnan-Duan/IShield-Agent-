"""统一响应格式和错误码定义"""
from flask import jsonify
from datetime import datetime, timezone
import uuid

# ── 业务错误码 ──────────────────────────────────────────────────────────────
class Err:
    OK              = ("OK",              200)
    BAD_REQUEST     = ("BAD_REQUEST",     400)
    VALIDATION_ERR  = ("VALIDATION_ERR",  400)
    UNAUTHORIZED    = ("UNAUTHORIZED",    401)
    FORBIDDEN       = ("FORBIDDEN",       403)
    NOT_FOUND       = ("NOT_FOUND",       404)
    RATE_LIMITED    = ("RATE_LIMITED",    429)
    INTERNAL_ERR    = ("INTERNAL_ERR",    500)
    SERVICE_UNAVAIL = ("SERVICE_UNAVAIL", 503)


def make_response(data=None, code="OK", message=None, request_id=None):
    """标准成功响应"""
    body = {
        "success": True,
        "code": code,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    if message:
        body["message"] = message
    if request_id:
        body["request_id"] = request_id
    return jsonify(body), 200


def make_error(error: tuple, message: str, request_id: str = None, details: dict = None):
    """标准错误响应"""
    code, status = error
    body = {
        "success": False,
        "code": code,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if request_id:
        body["request_id"] = request_id
    if details:
        body["details"] = details
    return jsonify(body), status


def get_request_id():
    """生成请求追踪 ID"""
    return str(uuid.uuid4())[:16]
