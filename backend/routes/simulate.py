"""Tool-call simulation route backed by the Runtime Gateway."""
import os
import sys

from flask import Blueprint, g, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from services.runtime_gateway import execute_runtime_request
from utils.response import make_response

simulate_bp = Blueprint("simulate", __name__, url_prefix="/api")


def _request_source_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    simulated = request.headers.get("X-Demo-Source-IP", "").strip()
    if simulated:
        return simulated.split(",")[0].strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


@simulate_bp.route("/simulate", methods=["POST"])
def simulate():
    if not request.is_json:
        raise ValidationError("请求 Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    action = str(data.get("action", "")).strip()
    params = data.get("params", "")
    if not action:
        raise ValidationError("action 参数不能为空")

    chain_id = data.get("chain_id")
    if chain_id:
        g.chain_id = chain_id

    result = execute_runtime_request(
        action=action,
        params=params,
        chain_id=chain_id,
        source_ip=data.get("source_ip") or _request_source_ip(),
        token_meta=getattr(g, "token_meta", None),
        trace_id=getattr(g, "request_id", None),
        actor=data.get("actor") or "agent",
    )
    g.chain_id = result.get("chain_id")
    return make_response(result, chain_id=result.get("chain_id"))
