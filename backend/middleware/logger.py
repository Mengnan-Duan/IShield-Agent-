"""结构化 JSON 日志中间件"""
from flask import request, g
from datetime import datetime, timezone
import uuid
import json
import logging
import os

# ── 日志目录 ────────────────────────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "app.log")


class JSONFormatter(logging.Formatter):
    """输出 JSON Lines 格式的日志"""
    def format(self, record):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        payload = {
            "timestamp":  dt.isoformat(),
            "level":      record.levelname,
            "logger":     record.name,
            "message":    record.getMessage(),
        }
        # 附加 request context
        if hasattr(record, "request_id"):
            payload["request_id"] = record.request_id
        if hasattr(record, "client_ip"):
            payload["client_ip"] = record.client_ip
        if hasattr(record, "method"):
            payload["method"] = record.method
        if hasattr(record, "path"):
            payload["path"] = record.path
        if hasattr(record, "status"):
            payload["status"] = record.status
        if hasattr(record, "duration_ms"):
            payload["duration_ms"] = record.duration_ms
        if hasattr(record, "extra"):
            payload.update(record.extra)
        return json.dumps(payload, ensure_ascii=False)


def get_logger(name="ishield"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        # File handler — JSON Lines
        fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(JSONFormatter())
        # Console handler — human readable
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        ch.setFormatter(logging.Formatter(
            "\033[1m[%(asctime)s]\033[0m %(levelname)-8s %(message)s",
            datefmt="%H:%M:%S"
        ))
        logger.addHandler(fh)
        logger.addHandler(ch)
    return logger


# ── Request ID 注入 ─────────────────────────────────────────────────────────
def setup_request_logging(app):
    """为 Flask app 注入请求 ID 和结构化日志"""
    logger = get_logger()

    @app.before_request
    def before():
        g.request_id = str(uuid.uuid4())[:16]
        g.start_time = datetime.now(timezone.utc)

    @app.after_request
    def after(response):
        duration_ms = int(
            (datetime.now(timezone.utc) - g.start_time).total_seconds() * 1000
        )
        # 从响应 body 中提取 threat 信息（如果有）
        extra = {}
        try:
            import flask
            if hasattr(g, "_threat_detected"):
                extra["threat_detected"] = g._threat_detected
            if hasattr(g, "_confidence"):
                extra["confidence"] = g._confidence
        except Exception:
            pass

        log_record = {
            "request_id": g.get("request_id", "?"),
            "client_ip":  request.remote_addr or "unknown",
            "method":     request.method,
            "path":       request.path,
            "status":     response.status_code,
            "duration_ms": duration_ms,
            "extra":      extra,
        }
        if response.status_code >= 500:
            logger.error("Request completed", extra=log_record)
        elif response.status_code >= 400:
            logger.warning("Request completed", extra=log_record)
        else:
            logger.info("Request completed", extra=log_record)

        # 将 request_id 注入响应头
        response.headers["X-Request-ID"] = g.get("request_id", "")
        return response
