"""文件读写沙箱 — 目录隔离 + 危险文件拦截 + 审计信息"""
import os, re, sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    SANDBOX_ROOT,
    SANDBOX_ALLOWED_READ_DIRS,
    SANDBOX_ALLOWED_WRITE_DIRS,
    SANDBOX_BLOCKED_FILENAMES,
    SANDBOX_MAX_FILE_SIZE,
)

ALLOWED_EXTENSIONS = {".txt", ".json", ".csv", ".log", ".md", ".yaml", ".yml", ".xml"}
MAX_FILE_SIZE = SANDBOX_MAX_FILE_SIZE

_BLOCKED_PREFIXES = [
    r"C:\\Windows", r"C:\\Program Files", r"C:\\Program Files \(x86\)",
    r"/etc/", r"/root/", r"/sys/", r"/proc/", r"/boot/",
    r"../../", r"../..", r"..\\..",
    r"/etc/passwd", r"/etc/shadow",
]
_BLOCKED_PATTERNS = [re.compile(p, re.I) for p in _BLOCKED_PREFIXES]


class SecurityBlocked(Exception):
    pass


class FileSandbox:
    """安全文件读写沙箱"""

    def __init__(self, root: str = None):
        self.root = Path(root or SANDBOX_ROOT or "./sandbox_files").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        for dirname in set(SANDBOX_ALLOWED_READ_DIRS) | set(SANDBOX_ALLOWED_WRITE_DIRS):
            (self.root / dirname).mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.root), 0o755)

    def _check_path(self, path: str, operation: str) -> Path:
        if not path or not str(path).strip():
            raise SecurityBlocked("文件路径不能为空")

        raw_path = str(path).replace("\\", "/").strip(" /")
        for pattern in _BLOCKED_PATTERNS:
            if pattern.search(raw_path):
                raise SecurityBlocked(f"禁止访问路径: {path}")

        filename = Path(raw_path).name.lower()
        if filename in {name.lower() for name in SANDBOX_BLOCKED_FILENAMES}:
            raise SecurityBlocked(f"禁止访问敏感文件: {filename}")
        if filename.endswith(".db"):
            raise SecurityBlocked("禁止直接访问数据库文件")

        top_level = raw_path.split("/", 1)[0]
        if operation == "read" and top_level not in SANDBOX_ALLOWED_READ_DIRS:
            raise SecurityBlocked(f"目录 {top_level} 不在读白名单内")
        if operation in {"write", "delete"} and top_level not in SANDBOX_ALLOWED_WRITE_DIRS:
            raise SecurityBlocked(f"目录 {top_level} 不在写白名单内")

        full = (self.root / raw_path).resolve()
        try:
            full.relative_to(self.root)
        except ValueError:
            raise SecurityBlocked(f"路径越界: {path} 不在沙箱目录内")
        return full

    def _check_file(self, path: Path):
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {path}")
        if path.is_dir():
            raise IsADirectoryError(f"路径是目录而非文件: {path}")
        if path.stat().st_size > MAX_FILE_SIZE:
            raise ValueError(f"文件超过大小限制({MAX_FILE_SIZE // 1024}KB): {path.name}")
        ext = path.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"不支持的文件类型: {ext}，仅支持: {', '.join(ALLOWED_EXTENSIONS)}")

    def preview(self, filename: str) -> dict:
        try:
            path = self._check_path(filename, "read")
            return self._result("executed", filename, "路径预检通过", path=path, mode="preview")
        except SecurityBlocked as e:
            return self._result("blocked", filename, str(e), reason="preview_blocked", mode="preview")

    def read(self, filename: str, source_ip: str = None) -> dict:
        try:
            path = self._check_path(filename, "read")
            self._check_file(path)
            content = path.read_text(encoding="utf-8", errors="replace")
            return self._result(
                "executed", filename, "文件读取成功", path=path,
                data={"content": content, "size": len(content), "source_ip": source_ip},
                severity=20,
            )
        except SecurityBlocked as e:
            return self._result("blocked", filename, str(e), reason="path_blocked", severity=85)
        except FileNotFoundError:
            return self._result("error", filename, "文件不存在", reason="not_found", severity=55)
        except Exception as e:
            return self._result("error", filename, str(e), reason="read_error", severity=60)

    def write(self, filename: str, content: str, append: bool = False, overwrite: bool = False, source_ip: str = None) -> dict:
        try:
            path = self._check_path(filename, "write")
            ext = path.suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise ValueError(f"不支持的文件类型: {ext}")
            if len(content.encode("utf-8")) > MAX_FILE_SIZE:
                raise ValueError(f"内容超过大小限制({MAX_FILE_SIZE // 1024}KB)")
            if path.exists() and not append and not overwrite:
                raise SecurityBlocked("目标文件已存在，默认禁止覆盖")

            path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if append else "w"
            with open(path, mode, encoding="utf-8") as f:
                f.write(content)

            return self._result(
                "executed", filename, "文件写入成功", path=path,
                data={"size": len(content), "mode": "append" if append else "overwrite" if overwrite else "write", "source_ip": source_ip},
                severity=20,
            )
        except SecurityBlocked as e:
            return self._result("blocked", filename, str(e), reason="write_blocked", severity=85)
        except Exception as e:
            return self._result("error", filename, str(e), reason="write_error", severity=60)

    def list(self, subdir: str = "") -> dict:
        try:
            base = self.root if not subdir else self._check_path(subdir, "read")
            if not base.is_dir():
                return self._result("error", subdir, "路径不是目录", reason="not_directory")
            files = []
            for f in base.iterdir():
                if f.is_file():
                    files.append({"name": f.name, "size": f.stat().st_size, "modified": f.stat().st_mtime})
            return {
                "status": "executed",
                "tool": "list_files",
                "mode": "real",
                "summary": "目录列举成功",
                "audit": {"target": str(base), "severity": 15, "threat_level": "low"},
                "data": {"files": files, "count": len(files)},
            }
        except SecurityBlocked as e:
            return self._result("blocked", subdir, str(e), reason="list_blocked", severity=80)
        except Exception as e:
            return self._result("error", subdir, str(e), reason="list_error", severity=60)

    def delete(self, filename: str) -> dict:
        try:
            path = self._check_path(filename, "delete")
            if not path.exists():
                return self._result("error", filename, "文件不存在", reason="not_found", severity=50)
            path.unlink()
            return self._result("executed", filename, "文件删除成功", path=path, severity=25)
        except SecurityBlocked as e:
            return self._result("blocked", filename, str(e), reason="delete_blocked", severity=85)
        except Exception as e:
            return self._result("error", filename, str(e), reason="delete_error", severity=60)

    def _result(self, status: str, filename: str, summary: str, path: Path = None,
                reason: str = None, data: dict = None, severity: int = 50, mode: str = "real") -> dict:
        return {
            "status": status,
            "tool": "file_access",
            "mode": mode,
            "summary": summary,
            "audit": {
                "target": filename,
                "resolved_path": str(path) if path else None,
                "reason": reason,
                "severity": severity,
                "threat_level": "high" if status == "blocked" else "low",
            },
            "data": data or {"filename": filename},
        }


_sandbox = None


def get_sandbox() -> FileSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = FileSandbox()
    return _sandbox
