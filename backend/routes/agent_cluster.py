"""Agent cluster supervision API."""
import os
import sys

from flask import Blueprint, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from services.agent_cluster import (
    get_cluster_replay,
    list_cluster_scenarios,
    list_cluster_sessions,
    role_matrix_payload,
    run_cluster_scenario,
)
from utils.response import Err, make_error, make_response


agent_cluster_bp = Blueprint("agent_cluster", __name__, url_prefix="/api/agent-cluster")


def _request_source_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").strip()
    simulated = request.headers.get("X-Demo-Source-IP", "").strip()
    if simulated:
        return simulated.split(",")[0].strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


@agent_cluster_bp.route("/scenarios", methods=["GET"])
def scenarios():
    return make_response(list_cluster_scenarios())


@agent_cluster_bp.route("/policy", methods=["GET"])
def policy():
    return make_response(role_matrix_payload())


@agent_cluster_bp.route("/sessions", methods=["GET"])
def sessions():
    limit = int(request.args.get("limit", 20))
    return make_response(list_cluster_sessions(limit=limit))


@agent_cluster_bp.route("/run", methods=["POST"])
def run_cluster():
    if not request.is_json:
        raise ValidationError("Content-Type must be application/json")
    payload = request.get_json(silent=True) or {}
    result = run_cluster_scenario(payload=payload, source_ip=payload.get("source_ip") or _request_source_ip())
    return make_response(result, chain_id=result.get("cluster_id"))


@agent_cluster_bp.route("/<cluster_id>/replay", methods=["GET"])
def replay(cluster_id):
    result = get_cluster_replay(cluster_id)
    if not result:
        return make_error(Err.NOT_FOUND, f"Agent cluster {cluster_id} not found")
    return make_response(result, chain_id=cluster_id)
