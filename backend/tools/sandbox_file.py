"""文件读写沙箱 — 路径白名单 + 禁止路径穿越"""
import os, re, sys, json
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SANDBOX_ROOT

ALLOWED_EXTENSIONS = {".txt", ".json", ".csv", ".log", ".md", ".yaml", ".yml", ".xml"}
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB

_BLOCKED_PREFIXES = [
    r"C:\\Windows", r"C:\\Program Files", r"C:\\Program Files \(x86\)",
    r"/etc/", r"/root/", r"/sys/", r"/proc/", r"/boot/",
    r"../../", r"../..", r"..\\..",
    r"/etc/passwd", r"/etc/shadow",
]
_BLOCKED_PATTERNS = [re.compile(p, re.I) for p in _BLOCKED_PREFIXES]


class SecurityBlocked(Exception):
    """沙箱安全违规异常"""
    pass


class FileSandbox:
    """安全文件读写沙箱"""

    def __init__(self, root: str = None):
        self.root = Path(root or SANDBOX_ROOT or "./sandbox_files").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.root), 0o755)

    def _check_path(self, path: str) -> Path:
        """安全检查并规范化路径"""
        # 检查禁用前缀
        for pattern in _BLOCKED_PATTERNS:
            if pattern.search(path):
                raise SecurityBlocked(f"禁止访问路径: {path}")

        # 路径规范化并检查是否在沙箱内
        full = (self.root / path).resolve()
        try:
            full.relative_to(self.root)
        except ValueError:
            raise SecurityBlocked(f"路径越界: {path} 不在沙箱目录内")

        return full

    def _check_file(self, path: Path):
        """检查文件安全性"""
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {path}")
        if path.is_dir():
            raise IsADirectoryError(f"路径是目录而非文件: {path}")
        if path.stat().st_size > MAX_FILE_SIZE:
            raise ValueError(f"文件超过大小限制({MAX_FILE_SIZE // 1024}KB): {path.name}")

        ext = path.suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"不支持的文件类型: {ext}，仅支持: {', '.join(ALLOWED_EXTENSIONS)}")

    def read(self, filename: str) -> dict:
        """
        读取文件内容。

        返回:
            {"status": "read", "filename": str, "content": str, "size": int}
        """
        try:
            path = self._check_path(filename)
            self._check_file(path)
            content = path.read_text(encoding="utf-8", errors="replace")
            return {
                "status": "read",
                "filename": filename,
                "content": content,
                "size": len(content),
                "path": str(path),
            }
        except SecurityBlocked as e:
            return {"status": "blocked", "filename": filename, "reason": str(e)}
        except FileNotFoundError:
            return {"status": "not_found", "filename": filename}
        except Exception as e:
            return {"status": "error", "filename": filename, "reason": str(e)}

    def write(self, filename: str, content: str, append: bool = False) -> dict:
        """
        写入文件内容。

        参数:
            filename: 文件名（相对路径）
            content:  文件内容
            append:   是否追加模式

        返回:
            {"status": "written"|"blocked"|"error", "filename": str, "size": int}
        """
        try:
            path = self._check_path(filename)

            # 检查扩展名
            ext = path.suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                raise ValueError(f"不支持的文件类型: {ext}")

            # 检查大小
            if len(content.encode("utf-8")) > MAX_FILE_SIZE:
                raise ValueError(f"内容超过大小限制({MAX_FILE_SIZE // 1024}KB)")

            mode = "a" if append else "w"
            with open(path, mode, encoding="utf-8") as f:
                f.write(content)

            return {
                "status": "written",
                "filename": filename,
                "size": len(content),
                "path": str(path),
                "mode": "append" if append else "overwrite",
            }
        except SecurityBlocked as e:
            return {"status": "blocked", "filename": filename, "reason": str(e)}
        except Exception as e:
            return {"status": "error", "filename": filename, "reason": str(e)}

    def list(self, subdir: str = "") -> dict:
        """列出沙箱目录中的文件"""
        try:
            base = self.root
            if subdir:
                base = self._check_path(subdir)

            if not base.is_dir():
                return {"status": "not_directory", "path": str(base)}

            files = []
            for f in base.iterdir():
                if f.is_file():
                    files.append({
                        "name": f.name,
                        "size": f.stat().st_size,
                        "modified": f.stat().st_mtime,
                    })

            return {"status": "listed", "path": str(base), "files": files, "count": len(files)}
        except SecurityBlocked:
            return {"status": "blocked", "reason": "路径越界"}
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    def delete(self, filename: str) -> dict:
        """删除文件"""
        try:
            path = self._check_path(filename)
            if not path.exists():
                return {"status": "not_found", "filename": filename}
            path.unlink()
            return {"status": "deleted", "filename": filename, "path": str(path)}
        except SecurityBlocked as e:
            return {"status": "blocked", "filename": filename, "reason": str(e)}
        except Exception as e:
            return {"status": "error", "filename": filename, "reason": str(e)}


# ── 全局单例 ────────────────────────────────────────────────────────────────
_sandbox = None

def get_sandbox() -> FileSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = FileSandbox()
    return _sandbox
