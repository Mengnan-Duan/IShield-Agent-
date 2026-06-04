"""全局异常处理中间件"""
from flask import jsonify, g
from werkzeug.exceptions import HTTPException
import traceback
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.response import make_error, Err
from middleware.logger import get_logger

logger = get_logger()


class BusinessError(Exception):
    """业务异常基类"""
    def __init__(self, message: str, code: tuple = Err.BAD_REQUEST, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class ValidationError(BusinessError):
    """输入校验异常"""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message, Err.VALIDATION_ERR, details)


class RateLimitError(BusinessError):
    """限流异常"""
    def __init__(self, message: str = "请求过于频繁"):
        super().__init__(message, Err.RATE_LIMITED)


def setup_error_handlers(app):
    """为 Flask app 注册全局异常处理器"""

    @app.errorhandler(BusinessError)
    def handle_business_error(e: BusinessError):
        logger.warning(f"Business error: {e.message}", extra={
            "path": getattr(g, "path", ""),
            "extra": e.details,
        })
        return make_error(
            e.code, e.message,
            request_id=getattr(g, "request_id", ""),
            details=e.details,
        )

    @app.errorhandler(HTTPException)
    def handle_http_exception(e: HTTPException):
        code_map = {
            404: Err.NOT_FOUND,
            405: Err.BAD_REQUEST,
        }
        code, status = code_map.get(e.code, (Err.BAD_REQUEST, e.code))
        return make_error(
            code,
            e.description or f"HTTP {e.code}",
            request_id=getattr(g, "request_id", ""),
        )

    @app.errorhandler(Exception)
    def handle_exception(e: Exception):
        """所有未捕获异常的最终兜底 — 永远不暴露堆栈"""
        exc_type = type(e).__name__
        exc_msg  = str(e)

        # 记录完整堆栈到日志文件（不返回给客户端）
        tb = traceback.format_exc()
        logger.error(
            f"Unhandled exception: {exc_type}: {exc_msg}",
            extra={
                "exception_type": exc_type,
                "exception_msg":  exc_msg,
                "traceback":      tb,
                "path":           getattr(g, "path", ""),
            }
        )

        # 根据异常类型给用户友好的错误信息
        if exc_type == "JSONDecodeError":
            user_msg = "请求 body 格式错误，请确保发送的是有效的 JSON"
        elif exc_type == "ConnectionError":
            user_msg = "后端服务连接异常，请稍后重试"
        elif exc_type == "Timeout":
            user_msg = "请求超时，请稍后重试"
        elif exc_type == "OperationalError":
            user_msg = "数据库操作异常，请稍后重试"
        else:
            user_msg = "服务器内部异常，请稍后重试"

        return make_error(
            Err.INTERNAL_ERR,
            user_msg,
            request_id=getattr(g, "request_id", ""),
        )
