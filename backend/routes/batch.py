"""批量检测路由"""
from flask import Blueprint, request

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_response
from utils.validators import validate_batch_texts, validate_text
from middleware.error_handler import ValidationError

from services.batch import batch_detect_sync

batch_bp = Blueprint("batch", __name__, url_prefix="/api/batch")


@batch_bp.route("/detect", methods=["POST"])
def batch_detect():
    if not request.is_json:
        raise ValidationError("Content-Type 必须是 application/json")

    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("无效的 JSON body")

    texts = data.get("texts", [])
    valid, err = validate_batch_texts(texts)
    if not valid:
        raise ValidationError(err)

    result = batch_detect_sync(texts)
    return make_response(result)
