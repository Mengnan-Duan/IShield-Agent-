from pathlib import Path
import sys


_DEF_RUNTIME_DIR_NAME = "runtime"


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_root() -> Path:
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return project_root()


def executable_root() -> Path:
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return project_root()


def runtime_root() -> Path:
    root = executable_root() / _DEF_RUNTIME_DIR_NAME if is_frozen() else project_root() / "backend"
    root.mkdir(parents=True, exist_ok=True)
    return root


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def bundled_path(*parts: str) -> Path:
    return bundle_root().joinpath(*parts)


def runtime_path(*parts: str) -> Path:
    path = runtime_root().joinpath(*parts)
    if path.suffix:
        ensure_dir(path.parent)
    else:
        ensure_dir(path)
    return path


def backend_data_dir() -> Path:
    return bundled_path("backend", "data")


def backend_policies_dir() -> Path:
    return bundled_path("backend", "policies")


def reports_dir() -> Path:
    return runtime_path("reports")


def logs_dir() -> Path:
    return runtime_path("logs")


def runtime_data_dir() -> Path:
    return runtime_path("data")


def static_root() -> Path:
    return bundle_root()
