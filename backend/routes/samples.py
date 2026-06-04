"""恶意样本库路由 — 查询、统计、导出归档样本"""
from flask import Blueprint, request, jsonify, Response
import csv
import io
import json

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.error_handler import ValidationError
from middleware.logger import get_logger
from utils.response import make_response, make_error, Err

from services.samples import (
    get_samples,
    get_sample_stats,
    get_categories,
    cleanup_old_samples,
)

logger = get_logger()
samples_bp = Blueprint("samples", __name__, url_prefix="/api/samples")


@samples_bp.route("", methods=["GET"])
def list_samples():
    """
    GET /api/samples
    查询恶意样本列表，支持分页和筛选。
    """
    try:
        limit         = min(int(request.args.get("limit", 50)), 200)
        offset        = max(int(request.args.get("offset", 0)), 0)
        category      = request.args.get("category") or None
        threat_level  = request.args.get("threat_level") or None
        min_conf      = request.args.get("min_confidence", type=int) or None
        date_from     = request.args.get("from") or None
        date_to       = request.args.get("to") or None

        samples = get_samples(
            limit=limit,
            offset=offset,
            category=category,
            threat_level=threat_level,
            min_confidence=min_conf,
            date_from=date_from,
            date_to=date_to,
        )

        return make_response({"samples": samples, "count": len(samples)})

    except ValueError as e:
        raise ValidationError(f"参数格式错误: {e}")


@samples_bp.route("/stats", methods=["GET"])
def sample_stats():
    """
    GET /api/samples/stats
    样本库统计：总数、分类分布、威胁等级分布、时间趋势。
    """
    stats = get_sample_stats()
    return make_response(stats)


@samples_bp.route("/categories", methods=["GET"])
def sample_categories():
    """
    GET /api/samples/categories
    返回样本库中出现过的所有威胁类别。
    """
    cats = get_categories()
    return make_response({"categories": cats})


@samples_bp.route("/export", methods=["GET"])
def export_samples():
    """
    GET /api/samples/export?format=csv|json
    导出样本库。
    """
    fmt = request.args.get("format", "csv")
    limit = min(int(request.args.get("limit", 1000)), 5000)

    samples = get_samples(limit=limit)
    if fmt == "json":
        return make_response({"samples": samples, "exported": len(samples)})

    # CSV export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "检测时间", "文本内容", "威胁类别", "威胁等级",
        "置信度", "命中规则", "检测原因", "来源"
    ])
    for s in samples:
        writer.writerow([
            s["id"],
            s["detected_at"],
            s["text"][:200],
            s["category"] or "",
            s["threat_level"] or "",
            s["confidence"] or "",
            json.dumps(s["rule_hits"], ensure_ascii=False)[:200],
            s["reason"] or "",
            s["source"],
        ])

    output.seek(0)
    csv_bytes = "\ufeff" + output.getvalue()
    return Response(
        csv_bytes,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=malicious_samples.csv"},
    )


@samples_bp.route("/cleanup", methods=["POST"])
def cleanup_samples():
    """
    POST /api/samples/cleanup
    清理超过 90 天的旧样本（可指定 days 参数）。
    仅供管理员操作。
    """
    data = request.get_json(silent=True) or {}
    days = int(data.get("days", 90))
    if days < 1:
        raise ValidationError("days 必须大于 0")
    deleted = cleanup_old_samples(days)
    return make_response({"deleted": deleted, "days": days})
