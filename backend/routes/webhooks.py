"""Webhook 管理 API"""
from flask import Blueprint, request, jsonify
from services.webhook_notifier import (
    register_webhook,
    unregister_webhook,
    list_webhooks,
    get_webhook_stats,
    fire_webhooks,
)

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")


@webhooks_bp.route("", methods=["GET"])
def get_webhooks():
    """列出所有已注册的 Webhook"""
    return jsonify({"code": "OK", "data": list_webhooks()})


@webhooks_bp.route("/stats", methods=["GET"])
def webhook_stats():
    """Webhook 统计"""
    return jsonify({"code": "OK", "data": get_webhook_stats()})


@webhooks_bp.route("/register", methods=["POST"])
def create_webhook():
    """注册 Webhook"""
    body = request.get_json() or {}
    name = body.get("name")
    url = body.get("url")
    if not name or not url:
        return jsonify({"code": "BAD_REQUEST", "message": "name 和 url 必填"}), 400
    result = register_webhook(
        name=name,
        url=url,
        format=body.get("format", "generic"),
        secret=body.get("secret", ""),
        min_severity=body.get("min_severity", "medium"),
        enabled=body.get("enabled", True),
    )
    return jsonify({"code": "OK", "data": result})


@webhooks_bp.route("/<name>", methods=["DELETE"])
def delete_webhook(name):
    """注销 Webhook"""
    result = unregister_webhook(name)
    if not result["success"]:
        return jsonify({"code": "NOT_FOUND", "message": f"未找到 Webhook: {name}"}), 404
    return jsonify({"code": "OK", "data": result})


@webhooks_bp.route("/test", methods=["POST"])
def test_webhook():
    """发送测试告警到所有 Webhook"""
    body = request.get_json() or {}
    result = fire_webhooks(
        event_type="测试告警",
        detail=body.get("message", "这是一条来自 IShield 的测试告警"),
        status="已发送",
        threat_level="medium",
        confidence=75,
        source_ip="127.0.0.1",
        action="webhook_test",
        tool_name="webhook_notifier",
        target="所有已注册 Webhook",
        rule_id="WEBHOOK-TEST-001",
        category="system",
        metadata={"test": True},
    )
    return jsonify({"code": "OK", "data": result})
