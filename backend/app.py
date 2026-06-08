"""
IShield Backend — 企业级 Flask 应用入口
所有业务逻辑下沉到 services/ 和 routes/，本文件只负责：
- 中间件装配
- 路由注册
- 应用启动
"""
from flask import Flask, send_from_directory, request
from flask_cors import CORS
import os

from middleware.logger import setup_request_logging, get_logger
from middleware.error_handler import setup_error_handlers
from middleware.rate_limiter import setup_rate_limiter
from middleware.behavior_guard import setup_behavior_guard
from middleware.auth import setup_auth

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
from services.websocket import events_stream

logger = get_logger()


def create_app():
    app = Flask(__name__, static_folder="..", static_url_path="")

    CORS(app, resources={
        r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Admin-Approval-Code"],
        }
    })

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

    @app.route("/api/events/stream")
    def sse_events():
        return events_stream()

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

    @app.route("/<path:path>")
    def static_files(path):
        fpath = os.path.join(app.static_folder, path)
        if os.path.isfile(fpath):
            return send_from_directory(app.static_folder, path)
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
    print("  Backend v2.0 — Enterprise Grade")
    print("=" * 60)
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
