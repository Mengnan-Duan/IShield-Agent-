"""
IShield Backend — 企业级 Flask 应用入口
所有业务逻辑下沉到 services/ 和 routes/，本文件只负责：
- 中间件装配
- 路由注册
- 应用启动
"""
from flask import Flask, send_from_directory, g
from flask_cors import CORS
import os

# ── 导入中间件 ────────────────────────────────────────────────────────────────
from middleware.logger import setup_request_logging, get_logger
from middleware.error_handler import setup_error_handlers
from middleware.rate_limiter import setup_rate_limiter

# ── 导入路由蓝图 ──────────────────────────────────────────────────────────────
from routes.detect import detect_bp
from routes.simulate import simulate_bp
from routes.events import events_bp
from routes.redteam import redteam_bp
from routes.batch import batch_bp
from routes.samples import samples_bp
from routes.policy import policy_bp
from services.websocket import events_stream

logger = get_logger()


def create_app():
    app = Flask(__name__, static_folder="..", static_url_path="")

    # ── CORS ────────────────────────────────────────────────────────────────
    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    })

    # ── 缓存控制 ─────────────────────────────────────────────────────────
    @app.after_request
    def add_cache_headers(response):
        if request.path == "/" or request.path.endswith(".html"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        elif request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-cache, no-store"
        elif not response.headers.get("Content-Type", "").startswith("text/"):
            response.headers["Cache-Control"] = "public, max-age=86400"
        return response

    # ── 中间件装配（顺序重要）───────────────────────────────────────────────
    from flask import request
    setup_request_logging(app)        # 结构化日志 + request_id
    setup_error_handlers(app)         # 全局异常处理
    setup_rate_limiter(app)             # 请求限流

    # ── 蓝图注册 ─────────────────────────────────────────────────────────
    app.register_blueprint(detect_bp)
    app.register_blueprint(simulate_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(redteam_bp)
    app.register_blueprint(batch_bp)
    app.register_blueprint(samples_bp)
    app.register_blueprint(policy_bp)

    # ── SSE 实时推送端点 ─────────────────────────────────────────────────
    @app.route("/api/events/stream")
    def sse_events():
        return events_stream()

    # ── 静态文件服务 ─────────────────────────────────────────────────────
    @app.route("/")
    def index():
        return send_from_directory(
            os.path.join(os.path.dirname(__file__), ".."),
            "frontend.html"
        )

    @app.route("/dashboard")
    def dashboard():
        return send_from_directory(
            os.path.join(os.path.dirname(__file__), ".."),
            "dashboard.html"
        )

    # ── 未匹配路由 ───────────────────────────────────────────────────────
    @app.route("/<path:path>")
    def static_files(path):
        fpath = os.path.join(app.static_folder, path)
        if os.path.isfile(fpath):
            return send_from_directory(app.static_folder, path)
        from middleware.error_handler import BusinessError
        from utils.response import Err
        raise BusinessError("资源不存在", Err.NOT_FOUND)

    # ── 启动时打印 ────────────────────────────────────────────────────────
    @app.before_request
    def log_start():
        pass  # request_id 等已在 logger.py 中处理

    return app


# ── 创建 app 实例（WSGI 服务器使用）─────────────────────────────────────────
app = create_app()


if __name__ == "__main__":
    print("=" * 60)
    print("  IShield Agent Security Platform")
    print("  Backend v2.0 — Enterprise Grade")
    print("=" * 60)
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
