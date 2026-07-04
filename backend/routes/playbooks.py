"""IShield v6.0 Attack Playbook API."""
import os
import sys

from flask import Blueprint, g, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from services.playbook_engine import latest_result, list_playbooks, regression_overview, run_playbooks
from utils.response import make_response


playbooks_bp = Blueprint("playbooks", __name__, url_prefix="/api/playbooks")


def _source_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


@playbooks_bp.route("", methods=["GET"])
def playbook_list():
    return make_response(list_playbooks())


@playbooks_bp.route("/run", methods=["POST"])
def playbook_run():
    if request.is_json is False:
        raise ValidationError("请求 Content-Type 必须是 application/json")
    payload = request.get_json(silent=True) or {}
    result = run_playbooks(
        payload,
        source_ip=_source_ip(),
        trace_id=getattr(g, "request_id", None),
        token_meta=getattr(g, "token_meta", None),
    )
    g.chain_id = result.get("run_id")
    return make_response(result, chain_id=result.get("run_id"))


@playbooks_bp.route("/<playbook_id>/result", methods=["GET"])
def playbook_result(playbook_id: str):
    result = latest_result(playbook_id)
    if result.get("status") == "not_found":
        raise ValidationError(f"未找到攻击剧本结果: {playbook_id}")
    return make_response(result)


@playbooks_bp.route("/regression", methods=["GET"])
def playbook_regression():
    return make_response(regression_overview())
