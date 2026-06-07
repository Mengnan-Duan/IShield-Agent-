import sys, os, socket, signal

# Resolve backend path relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(SCRIPT_DIR, "backend")
PID_FILE = os.path.join(SCRIPT_DIR, ".backend.pid")

sys.path.insert(0, BACKEND_DIR)


def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


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


def is_process_alive(pid):
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    except Exception:
        return False


def kill_old_server():
    pid = read_pid()
    if pid and is_process_alive(pid):
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.OpenProcess(0x0001, False, pid)  # TERMINATE
            kernel32.TerminateProcess(kernel32.OpenProcess(0x0001, False, pid), 0)
            print(f"[OK] Stopped old server process (PID {pid}).")
        except Exception:
            pass
        remove_pid()


if __name__ == "__main__":
    try:
        from app import create_app
        app = create_app()
    except ImportError as e:
        print("=" * 60)
        print("  [错误] 缺少依赖：", e)
        print("  请运行以下命令安装依赖：")
        print("  pip install flask flask_cors requests pyjwt")
        print("=" * 60)
        import sys; sys.exit(1)

    print("=" * 60)
    print("  IShield Agent Security Platform")
    print("  Backend v2.0 — Phase 4 Enhanced")
    print("=" * 60)
    print("  控制台：  http://127.0.0.1:5000/frontend.html")
    print("  分析看板：http://127.0.0.1:5000/dashboard")
    print("  端口 5000 | PID", os.getpid())
    print("=" * 60)

    import threading
    def _warmup():
        import time, urllib.request
        time.sleep(1.5)
        for _ in range(3):
            try:
                urllib.request.urlopen("http://127.0.0.1:5000/__internal__/warmup", timeout=5)
                print("[预热] 服务已就绪")
                return
            except Exception:
                time.sleep(1)

    threading.Thread(target=_warmup, daemon=True).start()
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
