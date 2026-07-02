"""Global exception handling for IShield APIs."""
import os
import sys
import traceback

from flask import g
from werkzeug.exceptions import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.logger import get_logger
from utils.response import Err, make_error

logger = get_logger()


class BusinessError(Exception):
    """Base exception for expected business errors."""

    def __init__(self, message: str, code: tuple = Err.BAD_REQUEST, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class ValidationError(BusinessError):
    """Input validation error."""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message, Err.VALIDATION_ERR, details)


class RateLimitError(BusinessError):
    """Rate limit error."""

    def __init__(self, message: str = "请求过于频繁，请稍后重试。"):
        super().__init__(message, Err.RATE_LIMITED)


def setup_error_handlers(app):
    """Register global Flask error handlers."""

    @app.errorhandler(BusinessError)
    def handle_business_error(e: BusinessError):
        logger.warning(
            f"Business error: {e.message}",
            extra={
                "path": getattr(g, "path", ""),
                "extra": e.details,
            },
        )
        return make_error(
            e.code,
            e.message,
            request_id=getattr(g, "request_id", ""),
            details=e.details,
            chain_id=getattr(g, "chain_id", None),
        )

    @app.errorhandler(HTTPException)
    def handle_http_exception(e: HTTPException):
        error_tuple = {
            404: Err.NOT_FOUND,
            405: Err.BAD_REQUEST,
            429: Err.RATE_LIMITED,
        }.get(e.code, Err.INTERNAL_ERR if (e.code or 500) >= 500 else Err.BAD_REQUEST)
        return make_error(
            error_tuple,
            e.description or f"HTTP {e.code}",
            request_id=getattr(g, "request_id", ""),
            chain_id=getattr(g, "chain_id", None),
            recoverable=(e.code or 500) >= 500,
        )

    @app.errorhandler(Exception)
    def handle_exception(e: Exception):
        """Final fallback: log full details, return a safe user-facing error."""
        exc_type = type(e).__name__
        exc_msg = str(e)
        logger.error(
            f"Unhandled exception: {exc_type}: {exc_msg}",
            extra={
                "exception_type": exc_type,
                "exception_msg": exc_msg,
                "traceback": traceback.format_exc(),
                "path": getattr(g, "path", ""),
            },
        )

        user_msg = {
            "JSONDecodeError": "请求 body 格式错误，请确认发送的是有效 JSON。",
            "ConnectionError": "后端服务连接异常，请稍后重试。",
            "Timeout": "请求超时，请稍后重试。",
            "OperationalError": "数据库操作异常，请稍后重试。",
        }.get(exc_type, "服务器内部异常，请稍后重试。")

        return make_error(
            Err.INTERNAL_ERR,
            user_msg,
            request_id=getattr(g, "request_id", ""),
            details={"exception_type": exc_type},
            chain_id=getattr(g, "chain_id", None),
            recoverable=True,
        )
