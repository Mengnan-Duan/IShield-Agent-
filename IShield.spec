# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import sys

project_root = Path.cwd()
backend_root = project_root / "backend"


def data_entry(src: Path, dest: str):
    return (str(src), dest)


def collect_first_existing(names, search_roots, dest="."):
    entries = []
    for name in names:
        for root in search_roots:
            candidate = root / name
            if candidate.exists():
                entries.append((str(candidate), dest))
                break
    return entries


conda_dll_roots = [
    Path(sys.prefix) / "Library" / "bin",
    Path(sys.base_prefix) / "Library" / "bin",
]

runtime_dlls = collect_first_existing(
    [
        "ffi.dll",
        "libexpat.dll",
        "libmpdec-4.dll",
        "liblzma.dll",
        "libbz2.dll",
        "LIBBZ2.dll",
        "sqlite3.dll",
    ],
    conda_dll_roots,
)


datas = [
    data_entry(project_root / "README.md", "."),
    data_entry(project_root / "frontend.html", "."),
    data_entry(project_root / "dashboard.html", "."),
    data_entry(project_root / "assets", "assets"),
    data_entry(backend_root / "config.py", "backend"),
    data_entry(backend_root / "data" / "benign_samples.json", "backend/data"),
    data_entry(backend_root / "data" / "signatures.json", "backend/data"),
    data_entry(backend_root / "data" / "test_samples.csv", "backend/data"),
    data_entry(backend_root / "data" / "test_suite.json", "backend/data"),
    data_entry(backend_root / "data" / "tool_permissions.json", "backend/data"),
    data_entry(backend_root / "playbooks", "backend/playbooks"),
    data_entry(backend_root / "policies", "backend/policies"),
]

hiddenimports = [
    "app",
    "config",
    "flask",
    "flask_cors",
    "requests",
    "openai",
    "dashscope",
]

block_cipher = None

a = Analysis(
    ['backend/run_backend.py'],
    pathex=[str(backend_root), str(project_root)],
    binaries=runtime_dlls,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='IShield',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='IShield',
)
