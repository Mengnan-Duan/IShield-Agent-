"""Token 管理路由 — 创建、吊销、轮换、列表"""
from flask import Blueprint, request, g
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from middleware.auth import require_permission
from utils.response import make_response
from services.token_manager import (
    create_token,
    revoke_token,
    rotate_token,
    list_tokens,
    validate_token,
)

tokens_bp = Blueprint("tokens", __name__, url_prefix="/api/tokens")


def _check_admin():
    import config
    if not getattr(config, "AUTH_ENABLED", False):
        return None  # dev mode: allow all
    meta = getattr(g, "token_meta", None)
    if not meta or meta.get("role") != "admin":
        from flask import jsonify
        return jsonify({"code": "FORBIDDEN", "success": False, "message": "Admin only"}), 403
    return None


@tokens_bp.route("/list", methods=["GET"])
def list_all_tokens():
    """GET /api/tokens/list — 列出所有 token（不返回密钥）"""
    tokens = list_tokens()
    return make_response({"tokens": tokens, "total": len(tokens)})


@tokens_bp.route("/create", methods=["POST"])
def create_new_token():
    """POST /api/tokens/create — 创建新 token"""
    if err := _check_admin():
        return err
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    if not name:
        raise ValidationError("缺少 name 字段")
    role = data.get("role", "operator")
    description = data.get("description", "")
    expires_days = data.get("expires_days")
    allowed_ips = data.get("allowed_ips")
    try:
        result = create_token(name, role, description, expires_days, allowed_ips)
        return make_response(result)
    except ValueError as e:
        raise ValidationError(str(e))


@tokens_bp.route("/revoke/<name>", methods=["POST"])
def revoke(name: str):
    """POST /api/tokens/revoke/<name> — 吊销 token"""
    if err := _check_admin():
        return err
    reason = request.get_json(silent=True) or {}
    ok = revoke_token(name, reason.get("reason", ""))
    if not ok:
        raise ValidationError(f"Token '{name}' 不存在")
    return make_response({"message": f"Token '{name}' 已吊销", "name": name})


@tokens_bp.route("/rotate/<name>", methods=["POST"])
def rotate(name: str):
    """POST /api/tokens/rotate/<name> — 轮换 token"""
    if err := _check_admin():
        return err
    result = rotate_token(name)
    if not result:
        raise ValidationError(f"Token '{name}' 不存在或已被吊销")
    return make_response(result)


@tokens_bp.route("/validate", methods=["POST"])
def validate():
    """POST /api/tokens/validate — 验证 token（含 IP 白名单检查）"""
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    ip = _get_client_ip()
    allowed, reason = validate_token(name, "", ip)
    return make_response({"name": name, "allowed": allowed, "reason": reason})


def _get_client_ip():
    from flask import request
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()
