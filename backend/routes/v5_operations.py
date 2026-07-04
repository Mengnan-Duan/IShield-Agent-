"""IShield v6.0 advanced operations API."""
import os
import sys

from flask import Blueprint, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.v5_operations import (
    build_benchmark_overview,
    build_response_center,
    build_system_audit,
    build_trace_graph,
    execute_response,
    run_benchmark,
    search_trace,
)
from utils.response import make_response


v5_ops_bp = Blueprint("v5_operations", __name__, url_prefix="/api")


@v5_ops_bp.route("/trace/graph", methods=["GET"])
def trace_graph():
    limit = request.args.get("limit", 80, type=int)
    chain_id = request.args.get("chain_id", "", type=str)
    return make_response(build_trace_graph(limit=limit, focus_chain_id=chain_id))


@v5_ops_bp.route("/trace/search", methods=["GET"])
def trace_search():
    query = request.args.get("q", "", type=str)
    limit = request.args.get("limit", 30, type=int)
    return make_response(search_trace(query=query, limit=limit))


@v5_ops_bp.route("/response/runbooks", methods=["GET"])
def response_runbooks():
    limit = request.args.get("limit", 30, type=int)
    return make_response(build_response_center(limit=limit))


@v5_ops_bp.route("/response/execute", methods=["POST"])
def response_execute():
    payload = request.get_json(silent=True) or {}
    return make_response(execute_response(payload), chain_id=payload.get("chain_id"))


@v5_ops_bp.route("/benchmark/overview", methods=["GET"])
def benchmark_overview():
    return make_response(build_benchmark_overview())


@v5_ops_bp.route("/benchmark/run", methods=["POST"])
def benchmark_run():
    payload = request.get_json(silent=True) or {}
    return make_response(run_benchmark(payload))


@v5_ops_bp.route("/system-audit", methods=["GET"])
def system_audit():
    return make_response(build_system_audit())
