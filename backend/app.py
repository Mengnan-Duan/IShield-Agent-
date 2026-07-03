"""
IShield Backend — 企业级 Flask 应用入口
所有业务逻辑下沉到 services/ 和 routes/，本文件只负责：
- 中间件装配
- 路由注册
- 应用启动
"""
from flask import Flask, send_from_directory, request
from flask_cors import CORS
from pathlib import Path

import config

from middleware.logger import setup_request_logging, get_logger
from middleware.error_handler import setup_error_handlers
from middleware.rate_limiter import setup_rate_limiter
from middleware.behavior_guard import setup_behavior_guard
from middleware.auth import setup_auth
from runtime_paths import static_root

from routes.detect import detect_bp
from routes.simulate import simulate_bp
from routes.events import events_bp
from routes.redteam import redteam_bp
from routes.batch import batch_bp
from routes.samples import samples_bp
from routes.policy import policy_bp
from routes.conversation import conversation_bp
from routes.behavior import behavior_bp
from routes.compliance import compliance_bp
from routes.audit import audit_bp
from routes.attack_chains import chains_bp
from routes.tokens import tokens_bp
from routes.ueba import ueba_bp
from routes.supply_chain import supply_bp
from routes.agent_monitor import agent_bp
from routes.tool_pending import pending_bp
from routes.webhooks import webhooks_bp
from routes.validation import validation_bp
from routes.agent_cluster import agent_cluster_bp
from routes.remediation import remediation_bp
from routes.closure import closure_bp
from services.websocket import events_stream

logger = get_logger()

# 全局退出标志（由 stop 端点设置，由 run_backend.py 的守护线程轮询并退出）
shutdown_event = None

def _get_shutdown_event():
    global shutdown_event
    if shutdown_event is None:
        import threading
        shutdown_event = threading.Event()
    return shutdown_event


def create_app():
    static_dir = static_root()
    app = Flask(__name__, static_folder=str(static_dir), static_url_path="")

    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Admin-Approval-Code"],
        }
    })

    @app.route("/api/__internal__/status")
    def internal_status():
        from routes.detect import _api_enabled, _api_provider
        return {
            "running": True,
            "status": "ok",
            "api_enabled": _api_enabled(),
            "api_provider": _api_provider(),
        }

    @app.route("/api/health", methods=["GET"])
    def health_check():
        """GET /api/health — 前端轮询后端就绪状态"""
        return {
            "status": "healthy",
            "version": "4.9.0",
        }

    @app.route("/api/__internal__/stop", methods=["POST"])
    def internal_stop():
        import threading
        evt = _get_shutdown_event()
        evt.set()
        return {"success": True, "message": "shutdown signal sent"}

    @app.after_request
    def add_cache_headers(response):
        if request.path == "/" or request.path.endswith(".html"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        elif request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-cache, no-store"
        elif not response.headers.get("Content-Type", "").startswith("text/"):
            response.headers["Cache-Control"] = "public, max-age=86400"
        return response

    setup_request_logging(app)
    setup_error_handlers(app)
    setup_rate_limiter(app)
    setup_behavior_guard(app)
    setup_auth(app)

    app.register_blueprint(detect_bp)
    app.register_blueprint(simulate_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(redteam_bp)
    app.register_blueprint(batch_bp)
    app.register_blueprint(samples_bp)
    app.register_blueprint(policy_bp)
    app.register_blueprint(conversation_bp)
    app.register_blueprint(behavior_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(chains_bp)
    app.register_blueprint(tokens_bp)
    app.register_blueprint(ueba_bp)
    app.register_blueprint(supply_bp)
    app.register_blueprint(agent_bp)
    app.register_blueprint(pending_bp)
    app.register_blueprint(webhooks_bp)
    app.register_blueprint(validation_bp)
    app.register_blueprint(agent_cluster_bp)
    app.register_blueprint(remediation_bp)
    app.register_blueprint(closure_bp)

    @app.route("/api/events/stream")
    def sse_events():
        return events_stream()

    static_dir = Path(app.static_folder)

    @app.route("/")
    def index():
        # v3.4 — 防止前端缓存：每次带 Cache-Control: no-cache
        resp = send_from_directory(static_dir, "frontend.html")
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp

    @app.route("/frontend.html")
    def frontend_html():
        # v3.4 — 兼容老 URL：访问 /frontend.html 时跳回 / 走 Hero 首页
        from flask import redirect
        return redirect("/", code=301)

    @app.route("/dashboard")
    def dashboard():
        resp = send_from_directory(static_dir, "dashboard.html")
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    @app.route("/<path:path>")
    def static_files(path):
        fpath = static_dir / path
        if fpath.is_file():
            return send_from_directory(static_dir, path)
        from middleware.error_handler import BusinessError
        from utils.response import Err
        raise BusinessError("资源不存在", Err.NOT_FOUND)

    @app.before_request
    def log_start():
        pass

    return app


app = create_app()


if __name__ == "__main__":
    print("=" * 60)
    print("  IShield Agent Security Platform")
    print("  Backend - Policy Hit Linkage")
    print("=" * 60)
    app.run(debug=False, host=config.BACKEND_HOST, port=config.BACKEND_PORT, threaded=True)
