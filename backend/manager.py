"""
IShield Manager — 服务管理器
独立进程，负责启动/停止 backend (run_backend.py)，前端通过 HTTP 与其通信。
路由基础路径：/api/manager
"""
import os
import sys
import signal
import subprocess
import threading
import time
from pathlib import Path

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
BACKEND_SCRIPT = SCRIPT_DIR / "run_backend.py"

# Backend process handle
_backend_process = None
_backend_lock = threading.Lock()


def _is_port_open(host, port, timeout=1):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _wait_backend_ready(port=5000, timeout=15, interval=0.5):
    """Wait for backend port to be open and responding."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _is_port_open("127.0.0.1", port):
            return True
        time.sleep(interval)
    return False


def start_backend():
    global _backend_process
    with _backend_lock:
        if _backend_process is not None and _backend_process.poll() is None:
            return {"success": True, "message": "Backend already running", "already_running": True}

        print("[Manager] Starting backend...")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        try:
            _backend_process = subprocess.Popen(
                [sys.executable, str(BACKEND_SCRIPT)],
                cwd=str(SCRIPT_DIR),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
        except Exception as e:
            return {"success": False, "error": f"Failed to start backend: {e}"}

    # Wait for backend to be ready
    if _wait_backend_ready(port=5000, timeout=15):
        return {"success": True, "message": "Backend started successfully"}
    else:
        # Backend may have crashed — clean up
        with _backend_lock:
            if _backend_process and _backend_process.poll() is not None:
                stdout, stderr = _backend_process.communicate(timeout=2)
                err_msg = (stderr or stdout or b"").decode("utf-8", errors="replace")[-500:]
                return {"success": False, "error": f"Backend crashed on startup: {err_msg}"}
        return {"success": True, "message": "Backend started (port check skipped)"}


def stop_backend():
    global _backend_process
    with _backend_lock:
        if _backend_process is None or _backend_process.poll() is not None:
            _backend_process = None
            return {"success": True, "message": "Backend already stopped"}

        print("[Manager] Stopping backend...")
        pid = _backend_process.pid
        try:
            if os.name == "nt":
                # Windows: kill process tree
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            pass

        _backend_process.terminate()
        try:
            _backend_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _backend_process.kill()
        _backend_process = None

    return {"success": True, "message": "Backend stopped"}


def get_backend_status():
    with _backend_lock:
        if _backend_process is not None and _backend_process.poll() is None:
            return {"running": True, "pid": _backend_process.pid}
        return {"running": False}


def create_app():
    from flask import Flask, jsonify, request
    from flask_cors import CORS

    app = Flask(__name__)
    CORS(app)

    @app.route("/api/manager/start", methods=["POST"])
    def _start():
        result = start_backend()
        status = 200 if result.get("success") else 500
        return jsonify(result), status

    @app.route("/api/manager/stop", methods=["POST"])
    def _stop():
        return jsonify(stop_backend())

    @app.route("/api/manager/status", methods=["GET"])
    def _status():
        return jsonify(get_backend_status())

    @app.route("/health", methods=["GET"])
    def _health():
        return jsonify({"ok": True})

    return app


app = create_app()


if __name__ == "__main__":
    print("=" * 55)
    print("  IShield Service Manager  (port 5001)")
    print("=" * 55)
    print(f"  Backend script: {BACKEND_SCRIPT}")
    print("=" * 55)
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
