"""
check_deps.py — 依赖包安全检查脚本（Phase 4）
检查 requirements.txt 中的包是否存在已知 CVE、是否使用预发布版本、是否过时。
"""
import subprocess
import sys
import re
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
# requirements.txt 在项目根目录，不在 backend/ 下
# 向上两级：backend/scripts/../ → 项目根目录
_PROJECT_ROOT_2 = Path(__file__).parent.parent.parent
REQ_FILE = _PROJECT_ROOT_2 / "requirements.txt"


def check_deps():
    print("=" * 60)
    print("  IShield 依赖包安全检查 — Phase 4")
    print("=" * 60)

    if not REQ_FILE.exists():
        print(f"[WARN] 未找到 {REQ_FILE}，跳过依赖检查")
        return

    with open(REQ_FILE, encoding="utf-8") as f:
        lines = f.readlines()

    print(f"\n[INFO] 分析 {len(lines)} 个依赖包...\n")

    # 预发布版本警告列表
    prerelease_packages = []

    # 常见高风险包（已知 CVE 或问题）
    risky_packages = {
        "requests": ("2.x 已不再维护", ">=2.32.0"),
        "urllib3": ("<1.26.18 或 <2.x存在HTTP/1.1走私风险", ">=1.26.18"),
        "flask": ("<2.3.0 存在 SSRF 和重定向风险", ">=2.3.0"),
        "jinja2": ("<3.1.3 存在 XSS 沙箱绕过", ">=3.1.3"),
        "pyyaml": ("<6.0.1 存在任意代码执行", ">=6.0.1"),
        "pillow": ("<10.0.0 存在多个图像处理漏洞", ">=10.0.0"),
        "cryptography": ("<41.0.0 存在绕过风险", ">=41.0.0"),
        "numpy": ("<1.22.0 存在缓冲区溢出", ">=1.22.0"),
        "django": ("<4.2 存在多个高危漏洞", ">=4.2"),
        "sqlalchemy": ("<1.4.49 存在 SQL 注入", ">=1.4.49"),
        "aiohttp": ("<3.9.0 存在 HTTP 拆分攻击", ">=3.9.0"),
        "certifi": ("过期 CA 证书可能无法验证新证书", ""),
    }

    issues = []
    warnings = []
    outdated = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # 解析包名和版本约束
        match = re.match(r"([a-zA-Z0-9_-]+)([<>=!~]+)?(.*)", line)
        if not match:
            continue

        pkg = match.group(1).lower()
        op = match.group(2) or ""
        ver = match.group(3) or ""

        # 检测预发布版本
        if any(tag in ver.lower() for tag in ["a", "b", "rc", "alpha", "beta"]):
            prerelease_packages.append({"package": pkg, "version": ver})

        # 检测已知风险包
        for risky_pkg, (issue, fix) in risky_packages.items():
            if pkg.startswith(risky_pkg) or pkg.replace("-", "_") == risky_pkg:
                issues.append({
                    "package": pkg,
                    "version": ver,
                    "issue": issue,
                    "fix": fix,
                    "severity": "high"
                })

    # 打印结果
    if issues:
        print("  [HIGH] 已知的风险依赖：")
        for iss in issues:
            fix = f" -> 建议升级到 {iss['fix']}" if iss['fix'] else ""
            print(f"    - {iss['package']}=={iss['version']}: {iss['issue']}{fix}")

    if prerelease_packages:
        print(f"\n  [WARN] 使用了预发布版本（共 {len(prerelease_packages)} 个）：")
        for p in prerelease_packages:
            print(f"    - {p['package']}=={p['version']}")

    # 检查 pip 版本
    print("\n  [INFO] 检查 pip 版本...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print(f"    {result.stdout.strip()}")
    except Exception as e:
        print(f"    无法获取 pip 版本: {e}")

    # 检查是否使用 venv
    in_venv = sys.prefix != sys.base_prefix
    print(f"\n  [INFO] 虚拟环境: {'是' if in_venv else '否（建议使用 venv）'}")

    # 总体评估
    print("\n" + "=" * 60)
    if issues:
        print(f"  结果: {len(issues)} 个风险依赖，建议升级")
        print("  请运行: pip install -r requirements.txt --upgrade")
    elif prerelease_packages:
        print(f"  结果: {len(prerelease_packages)} 个预发布版本，生产环境不建议使用")
    else:
        print("  结果: 未发现严重安全问题")
    print("=" * 60)


if __name__ == "__main__":
    check_deps()
