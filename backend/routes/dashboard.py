"""IShield v5.8 operational dashboard API."""
import os
import sys

from flask import Blueprint, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.dashboard import build_dashboard_live, build_dashboard_overview, build_dashboard_timeline, build_live_status
from utils.response import make_response


dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/overview", methods=["GET"])
def dashboard_overview():
    limit = request.args.get("limit", 12, type=int)
    return make_response(build_dashboard_overview(limit=limit))


@dashboard_bp.route("/timeline", methods=["GET"])
def dashboard_timeline():
    return make_response({"timeline": build_dashboard_timeline()})


@dashboard_bp.route("/live-status", methods=["GET"])
def dashboard_live_status():
    return make_response(build_live_status())


@dashboard_bp.route("/live", methods=["GET"])
def dashboard_live():
    limit = request.args.get("limit", 25, type=int)
    return make_response(build_dashboard_live(limit=limit))
