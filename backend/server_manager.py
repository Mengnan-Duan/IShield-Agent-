"""
server_manager.py — 后端服务管理器
独立进程运行于端口 5001，负责：
- 启动 / 停止 / 重启后端服务（端口 5000）
- 端口占用检测与旧进程清理
- 状态上报（PID / 运行时间 / 版本）
- 实时日志流
"""
from flask import Flask, jsonify, request, Response
import subprocess
import sys
import os
import socket
import signal
import time
import threading
import json
import ctypes
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(SCRIPT_DIR)
PID_FILE = os.path.join(SCRIPT_DIR, ".backend.pid")
STATUS_FILE = os.path.join(BACKEND_DIR, "data", "server_status.json")
MANAGER_PORT = 5001
BACKEND_PORT = 5000
BACKEND_HOST = "0.0.0.0"
LOG_FILE = os.path.join(SCRIPT_DIR, "backend", "logs", "server_manager.log")

app = Flask(__name__)
_lock = threading.Lock()
_process = None
_start_time = None


# ── 工具函数 ──────────────────────────────────────────────────────────────────

def is_port_in_use(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


def is_process_alive(pid):
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    except Exception:
        return False


def read_pid():
    try:
        with open(PID_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def write_pid(pid):
    with open(PID_FILE, "w") as f:
        f.write(str(pid))


def remove_pid():
    try:
        os.remove(PID_FILE)
    except FileNotFoundError:
        pass


def ensure_log_dir():
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


def log_msg(msg):
    ensure_log_dir()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    print(line.rstrip())


# ── 后端进程管理 ──────────────────────────────────────────────────────────────

def get_uptime():
    if _start_time is None:
        return 0
    return round(time.time() - _start_time)


def get_backend_status():
    pid = read_pid()
    alive = pid and is_process_alive(pid)
    port_used = is_port_in_use(BACKEND_PORT)
    return {
        "running": alive and port_used,
        "pid": pid,
        "port": BACKEND_PORT,
        "uptime": get_uptime(),
        "uptime_text": _format_uptime(get_uptime()),
        "port_in_use": port_used,
        "manager_port": MANAGER_PORT,
        "version": "3.4.0",
        "release": "3.4.0",
    }


def _format_uptime(seconds):
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


def save_status(status):
    try:
        os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(status, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def stop_backend(force=False):
    global _process, _start_time
    pid = read_pid()
    if not pid:
        log_msg("[STOP] No PID file found, backend not running.")
        return True

    if not is_process_alive(pid):
        log_msg(f"[STOP] PID {pid} is not alive, cleaning up.")
        remove_pid()
        return True

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x0001, False, pid)
        if handle:
            kernel32.GenerateConsoleCtrlEvent(0, pid)
            time.sleep(0.5)
            if not force:
                kernel32.TerminateProcess(handle, 0)
            kernel32.CloseHandle(handle)
        log_msg(f"[STOP] Sent termination signal to PID {pid}.")
    except Exception as e:
        log_msg(f"[STOP] Error during stop: {e}")

    remove_pid()
    _start_time = None

    if _process and _process.poll() is None:
        try:
            _process.terminate()
            _process.wait(timeout=5)
        except Exception:
            try:
                _process.kill()
            except Exception:
                pass
    _process = None
    return True


def start_backend():
    global _process, _start_time
    status = get_backend_status()
    if status["running"]:
        log_msg("[START] Backend already running.")
        return status

    if is_port_in_use(BACKEND_PORT):
        log_msg(f"[START] Port {BACKEND_PORT} is occupied, attempting to free it.")
        pid = _find_process_by_port(BACKEND_PORT)
        if pid:
            _kill_by_pid(pid)
        time.sleep(1)

    run_py = os.path.join(BACKEND_DIR, "run_backend.py")
    if not os.path.exists(run_py):
        run_py = os.path.join(BACKEND_DIR, "app.py")
    log_msg(f"[START] Launching backend: {run_py}")
    try:
        _process = subprocess.Popen(
            [sys.executable, run_py],
            cwd=SCRIPT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        write_pid(_process.pid)
        _start_time = time.time()
        log_msg(f"[START] Backend started, PID {_process.pid}.")

        time.sleep(2)
        for _ in range(20):
            if is_port_in_use(BACKEND_PORT):
                log_msg("[START] Backend is ready on port 5000.")
                # v3.4: warmup
                try:
                    import urllib.request
                    urllib.request.urlopen(f"http://127.0.0.1:{BACKEND_PORT}/__internal__/warmup", timeout=5)
                    log_msg("[START] Backend warmup complete.")
                except Exception:
                    pass
                status = get_backend_status()
                save_status(status)
                return status
            time.sleep(0.5)

        log_msg("[START] WARNING: Backend may not be ready, but continuing.")
        return get_backend_status()
    except Exception as e:
        log_msg(f"[START] Failed to start backend: {e}")
        return {"error": str(e), "running": False}


def _find_process_by_port(port):
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        for line in result.stdout.splitlines():
            if f":{port}" in line:
                parts = line.split()
                for p in reversed(parts):
                    try:
                        return int(p)
                    except ValueError:
                        continue
    except Exception:
        pass
    return None


def _kill_by_pid(pid):
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x0001, False, pid)
        if handle:
            kernel32.TerminateProcess(handle, 0)
            kernel32.CloseHandle(handle)
            log_msg(f"[KILL] Killed process {pid}.")
    except Exception as e:
        log_msg(f"[KILL] Failed to kill PID {pid}: {e}")


def restart_backend():
    log_msg("[RESTART] Stopping backend...")
    stop_backend(force=True)
    time.sleep(2)
    log_msg("[RESTART] Starting backend...")
    return start_backend()


# ── 路由 ──────────────────────────────────────────────────────────────────────

@app.route("/api/manager/status", methods=["GET"])
def api_status():
    status = get_backend_status()
    save_status(status)
    return jsonify({"success": True, "data": status})


@app.route("/api/manager/start", methods=["POST"])
def api_start():
    with _lock:
        status = start_backend()
    return jsonify({"success": status.get("running", False), "data": status})


@app.route("/api/manager/stop", methods=["POST"])
def api_stop():
    with _lock:
        ok = stop_backend(force=False)
        save_status({"running": False, "port": BACKEND_PORT, "pid": None})
    return jsonify({"success": ok, "data": {"running": False}})


@app.route("/api/manager/restart", methods=["POST"])
def api_restart():
    with _lock:
        ok = restart_backend()
    return jsonify({"success": ok.get("running", False), "data": ok})


@app.route("/api/manager/logs", methods=["GET"])
def api_logs():
    lines = min(int(request.args.get("lines", 50)), 200)
    ensure_log_dir()
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
        log_lines = all_lines[-lines:]
        return Response(
            "\n".join(log_lines),
            mimetype="text/plain",
            headers={"Cache-Control": "no-cache"}
        )
    except FileNotFoundError:
        return Response("", mimetype="text/plain")


@app.route("/api/manager/health", methods=["GET"])
def api_health():
    return jsonify({"success": True, "manager": "ok"})


# ── 信号处理 ──────────────────────────────────────────────────────────────────

def cleanup(signum=None, frame=None):
    log_msg("[EXIT] Manager shutting down, stopping backend...")
    stop_backend(force=True)
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


# ── 启动时恢复后端状态 ────────────────────────────────────────────────────────

def restore_backend_state():
    pid = read_pid()
    if pid and is_process_alive(pid) and is_port_in_use(BACKEND_PORT):
        global _start_time
        _start_time = time.time()
        log_msg(f"[RECOVER] Backend already running, PID {pid}.")
    else:
        if pid:
            log_msg(f"[RECOVER] Stale PID file (PID {pid} not alive), cleaning up.")
            remove_pid()


if __name__ == "__main__":
    print("=" * 60)
    print("  IShield Server Manager")
    print("  IShield v3.4.0 — One-Click Backend Control")
    print("=" * 60)
    print(f"  Manager Port: {MANAGER_PORT}")
    print(f"  Backend Port: {BACKEND_PORT}")
    print(f"  PID File: {PID_FILE}")
    print("=" * 60)

    restore_backend_state()
    app.run(debug=False, host="0.0.0.0", port=MANAGER_PORT, threaded=True)
