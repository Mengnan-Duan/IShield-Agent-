"""Token 管理路由 — 创建、吊销、轮换、列表"""
from flask import Blueprint, request, g
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from utils.response import make_response
from services.token_manager import (
    create_token,
    revoke_token,
    rotate_token,
    list_tokens,
    validate_token,
    create_approval_code,
    verify_approval_code,
)


tokens_bp = Blueprint("tokens", __name__, url_prefix="/api/tokens")


ADMIN_APPROVAL_ACTIONS = {"create", "revoke", "rotate"}


def _check_admin():
    import config
    if not getattr(config, "AUTH_ENABLED", False):
        return None
    meta = getattr(g, "token_meta", None)
    if not meta or meta.get("role") != "admin":
        from flask import jsonify
        return jsonify({"code": "FORBIDDEN", "success": False, "message": "Admin only"}), 403
    return None


def _require_admin_approval(action: str):
    meta = getattr(g, "token_meta", None) or {}
    if meta.get("role") != "admin":
        return None
    code = request.headers.get("X-Admin-Approval-Code", "").strip()
    if not code:
        approval = create_approval_code(meta.get("name", "admin"), action)
        from flask import jsonify
        return jsonify({
            "code": "APPROVAL_REQUIRED",
            "success": False,
            "message": f"High-risk admin action '{action}' requires approval code.",
            "approval_code": approval["code"],
            "expires_at": approval["expires_at"],
        }), 403
    ok, reason = verify_approval_code(meta.get("name", "admin"), action, code)
    if not ok:
        from flask import jsonify
        return jsonify({
            "code": "APPROVAL_INVALID",
            "success": False,
            "message": reason,
        }), 403
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
    if err := _require_admin_approval("create"):
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
    scopes = data.get("scopes")
    allowed_tools = data.get("allowed_tools")
    constraints = data.get("constraints")
    write_access = data.get("write_access")
    requires_approval = data.get("requires_approval")
    try:
        result = create_token(
            name=name,
            role=role,
            description=description,
            expires_days=expires_days,
            allowed_ips=allowed_ips,
            scopes=scopes,
            allowed_tools=allowed_tools,
            constraints=constraints,
            write_access=write_access,
            requires_approval=requires_approval,
        )
        return make_response(result)
    except ValueError as e:
        raise ValidationError(str(e))


@tokens_bp.route("/revoke/<name>", methods=["POST"])
def revoke(name: str):
    """POST /api/tokens/revoke/<name> — 吊销 token"""
    if err := _check_admin():
        return err
    if err := _require_admin_approval("revoke"):
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
    if err := _require_admin_approval("rotate"):
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
    presented = data.get("token", "")
    ip = _get_client_ip()
    allowed, reason, meta = validate_token(name, presented, ip)
    return make_response({"name": name, "allowed": allowed, "reason": reason, "meta": meta})


def _get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()
