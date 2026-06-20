import atexit
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from contextlib import closing

from runtime_paths import executable_root, runtime_path

# Resolve backend path relative to this script
SCRIPT_DIR = executable_root()
BACKEND_DIR = str(executable_root())
PID_FILE = runtime_path(".backend.pid")
PORT = int(os.environ.get("BACKEND_PORT", 5000))
HOST = os.environ.get("BACKEND_HOST", "0.0.0.0")
LOCAL_HOST = os.environ.get("BACKEND_LOCAL_HOST", "127.0.0.1")
STOP_ENDPOINT = f"http://{LOCAL_HOST}:{PORT}/api/__internal__/stop"
STATUS_ENDPOINT = f"http://{LOCAL_HOST}:{PORT}/api/__internal__/status"
WARMUP_ENDPOINT = STATUS_ENDPOINT
FRONTEND_URL = f"http://{LOCAL_HOST}:{PORT}/frontend.html"

sys.path.insert(0, BACKEND_DIR)


def is_port_in_use(port, host=LOCAL_HOST):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(1)
        return sock.connect_ex((host, port)) == 0


def wait_for_port_release(port, timeout=5.0, interval=0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_port_in_use(port):
            return True
        time.sleep(interval)
    return not is_port_in_use(port)


def read_pid():
    try:
            return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def write_pid(pid):
    PID_FILE.write_text(str(pid), encoding="utf-8")


def remove_pid():
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


def is_process_alive(pid):
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        process_query_limited_information = 0x1000
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    except Exception:
        return False


def terminate_process(pid):
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        process_terminate = 0x0001
        handle = kernel32.OpenProcess(process_terminate, False, pid)
        if not handle:
            return False
        try:
            return bool(kernel32.TerminateProcess(handle, 0))
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return False


def get_listening_pid(port):
    try:
        output = subprocess.check_output(
            ["netstat", "-ano"],
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        return None

    port_suffix = f":{port}"
    for line in output.splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local_address = parts[1]
        if not local_address.endswith(port_suffix):
            continue
        try:
            return int(parts[-1])
        except ValueError:
            return None
    return None


def request_graceful_stop(timeout=2):
    request = urllib.request.Request(STOP_ENDPOINT, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False


def is_backend_service_running(timeout=2):
    try:
        with urllib.request.urlopen(STATUS_ENDPOINT, timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False


def stop_tracked_process(pid):
    print(f"[启动] 检测到旧实例 PID {pid}，尝试优雅停止...")
    request_graceful_stop()
    if wait_for_port_release(PORT, timeout=5):
        remove_pid()
        return True

    if terminate_process(pid):
        print(f"[启动] 已强制结束旧实例 PID {pid}。")
        if wait_for_port_release(PORT, timeout=3):
            remove_pid()
            return True

    raise RuntimeError(f"旧实例 PID {pid} 未能释放端口 {PORT}。")


def stop_untracked_backend_process():
    print("[启动] 检测到未登记的后端实例，尝试优雅停止...")
    request_graceful_stop()
    if wait_for_port_release(PORT, timeout=5):
        return True

    listening_pid = get_listening_pid(PORT)
    if listening_pid and terminate_process(listening_pid):
        print(f"[启动] 已强制结束占用端口 {PORT} 的后端实例 PID {listening_pid}。")
        if wait_for_port_release(PORT, timeout=3):
            return True

    raise RuntimeError(f"检测到后端仍占用端口 {PORT}，但停机失败。")


def ensure_single_instance():
    pid = read_pid()

    if pid and is_process_alive(pid):
        if stop_tracked_process(pid):
            return

    if pid:
        remove_pid()

    if is_port_in_use(PORT):
        if is_backend_service_running():
            if stop_untracked_backend_process():
                return
        raise RuntimeError(f"端口 {PORT} 已被其他进程占用，请先关闭占用该端口的程序。")


def cleanup_pid():
    current_pid = read_pid()
    if current_pid == os.getpid():
        remove_pid()


def register_cleanup_hooks():
    atexit.register(cleanup_pid)


def open_frontend_when_ready(delay=1.5, retries=10, interval=1.0):
    def _open():
        time.sleep(delay)
        for _ in range(retries):
            try:
                with urllib.request.urlopen(STATUS_ENDPOINT, timeout=5) as response:
                    if response.status == 200:
                        webbrowser.open(FRONTEND_URL)
                        print(f"[启动] 已打开前端页面：{FRONTEND_URL}")
                        return
            except Exception:
                pass
            time.sleep(interval)
        print(f"[启动] 服务已启动，请手动打开：{FRONTEND_URL}")

    import threading

    threading.Thread(target=_open, daemon=True).start()


if __name__ == "__main__":
    try:
        from app import create_app

        app = create_app()
    except ImportError as error:
        print("=" * 60)
        print("  [错误] 缺少依赖：", error)
        print("  请运行以下命令安装依赖：")
        print("  pip install flask flask_cors requests pyjwt")
        print("=" * 60)
        input("按回车键退出...")
        raise SystemExit(1)

    ensure_single_instance()
    write_pid(os.getpid())
    register_cleanup_hooks()

    print("=" * 60)
    print("  IShield Agent Security Platform")
    print("  Backend v2.0 — Phase 4 Enhanced")
    print("=" * 60)
    print(f"  控制台：  {FRONTEND_URL}")
    print(f"  分析看板：http://{LOCAL_HOST}:{PORT}/dashboard")
    print(f"  端口 {PORT} | PID {os.getpid()}")
    print("=" * 60)

    open_frontend_when_ready()

    import threading

    def _warmup():
        time.sleep(1.5)
        for _ in range(3):
            try:
                urllib.request.urlopen(WARMUP_ENDPOINT, timeout=5)
                print("[预热] 服务已就绪")
                return
            except Exception:
                time.sleep(1)

    threading.Thread(target=_warmup, daemon=True).start()

    # 守护线程：监听 shutdown_event，超时后强制退出进程
    import app as _app_module
    def _shutdown_watcher():
        evt = _app_module._get_shutdown_event()
        evt.wait()
        print("[关闭] 收到停止信号，正在退出...")
        import os
        os._exit(0)

    shutdown_watchdog = threading.Thread(target=_shutdown_watcher, daemon=True)
    shutdown_watchdog.start()

    app.run(debug=False, host=HOST, port=PORT, threaded=True)
