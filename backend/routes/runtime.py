"""IShield v5.8 external Agent runtime protocol API."""
import os
import sys

from flask import Blueprint, g, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from services.runtime_diagnostics import diagnostic_playbooks, latest_diagnostic, run_runtime_diagnostics
from services.runtime_protocol import decide_step, ingest_step, list_sessions, sdk_config
from utils.response import make_response


runtime_bp = Blueprint("runtime", __name__, url_prefix="/api/runtime")


def _source_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


@runtime_bp.route("/ingest", methods=["POST"])
def runtime_ingest():
    if not request.is_json:
        raise ValidationError("请求 Content-Type 必须是 application/json")
    payload = request.get_json(silent=True)
    if payload is None:
        raise ValidationError("无效的 JSON body")
    result = ingest_step(
        payload,
        source_ip=_source_ip(),
        trace_id=getattr(g, "request_id", None),
    )
    g.chain_id = result.get("chain_id")
    return make_response(result, chain_id=result.get("chain_id"))


@runtime_bp.route("/decision", methods=["POST"])
def runtime_decision():
    if not request.is_json:
        raise ValidationError("请求 Content-Type 必须是 application/json")
    payload = request.get_json(silent=True)
    if payload is None:
        raise ValidationError("无效的 JSON body")
    result = decide_step(
        payload,
        source_ip=_source_ip(),
        trace_id=getattr(g, "request_id", None),
        token_meta=getattr(g, "token_meta", None),
    )
    g.chain_id = result.get("chain_id")
    return make_response(result, chain_id=result.get("chain_id"))


@runtime_bp.route("/sessions", methods=["GET"])
def runtime_sessions():
    limit = request.args.get("limit", 50, type=int)
    return make_response(list_sessions(limit=limit))


@runtime_bp.route("/sdk-config", methods=["GET"])
def runtime_sdk_config():
    base_url = request.args.get("base_url") or request.host_url.rstrip("/")
    return make_response(sdk_config(base_url=base_url))


@runtime_bp.route("/diagnostics/playbooks", methods=["GET"])
def runtime_diagnostic_playbooks():
    return make_response(diagnostic_playbooks())


@runtime_bp.route("/diagnostics/latest", methods=["GET"])
def runtime_diagnostic_latest():
    return make_response(latest_diagnostic())


@runtime_bp.route("/diagnostics", methods=["POST"])
def runtime_diagnostics():
    payload = request.get_json(silent=True) or {}
    result = run_runtime_diagnostics(
        payload,
        source_ip=_source_ip(),
        trace_id=getattr(g, "request_id", None),
    )
    g.chain_id = (result.get("results") or [{}])[0].get("chain_id")
    return make_response(result, chain_id=g.chain_id)
