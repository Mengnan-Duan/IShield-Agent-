"""UEBA 路由 — Phase 4"""
from flask import Blueprint, jsonify
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response
from services.ueba import get_ueba_engine

ueba_bp = Blueprint("ueba", __name__, url_prefix="/api/ueba")


@ueba_bp.route("/summary", methods=["GET"])
def ueba_summary():
    """GET /api/ueba/summary — 全局 UEBA 摘要"""
    engine = get_ueba_engine()
    return make_response(engine.get_summary())


@ueba_bp.route("/ip/<ip>", methods=["GET"])
def ueba_ip(ip: str):
    """GET /api/ueba/ip/<ip> — IP 基线报告"""
    engine = get_ueba_engine()
    report = engine.get_ip_report(ip)
    return make_response(report)


@ueba_bp.route("/token/<name>", methods=["GET"])
def ueba_token(name: str):
    """GET /api/ueba/token/<name> — Token 基线报告"""
    engine = get_ueba_engine()
    report = engine.get_token_report(name)
    return make_response(report)


@ueba_bp.route("/clear/ip/<ip>", methods=["POST"])
def ueba_clear_ip(ip: str):
    """POST /api/ueba/clear/ip/<ip> — 清除 IP 基线数据"""
    engine = get_ueba_engine()
    engine.clear_ip(ip)
    return make_response({"message": f"IP {ip} 基线已清除", "ip": ip})


@ueba_bp.route("/clear/token/<name>", methods=["POST"])
def ueba_clear_token(name: str):
    """POST /api/ueba/clear/token/<name> — 清除 Token 基线数据"""
    engine = get_ueba_engine()
    engine.clear_token(name)
    return make_response({"message": f"Token {name} 基线已清除", "name": name})
