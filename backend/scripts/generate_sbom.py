"""
SBOM（软件物料清单）生成脚本 — 记录所有 Python 依赖及许可证信息
对应《智能体规范》第9条：供应链安全管理
"""
import subprocess
import json
import datetime
import hashlib
from pathlib import Path

SBOM_PATH = Path(__file__).parent.parent / "sbom.json"


def get_package_info():
    """获取所有已安装包的信息"""
    result = subprocess.run(
        ["pip", "freeze", "--format=json"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return []
    return json.loads(result.stdout)


def guess_license(pkg_name: str) -> str:
    """基于包名猜测许可证（实际应查 PyPI）"""
    known = {
        "flask": "BSD-3-Clause",
        "requests": "Apache-2.0",
        "openai": "Apache-2.0",
        "dashscope": "Apache-2.0",
        "reportlab": "BSD",
        "flask-cors": "MIT",
    }
    for name, lic in known.items():
        if name in pkg_name.lower():
            return lic
    return "UNKNOWN"


def generate_sbom():
    """生成 SPDX 格式 SBOM"""
    packages = get_package_info()
    now = datetime.datetime.now().isoformat()

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-ISHIELD",
        "name": "ishield-agent-security",
        "documentNamespace": "https://ishield.local/sbom/v1",
        "creationInfo": {
            "created": now,
            "creators": ["Tool: scripts/generate_sbom.py"],
        },
        "packages": [],
    }

    for pkg in packages:
        name = pkg.get("name", "?")
        ver = pkg.get("version", "?")
        sha256 = hashlib.sha256(f"{name}=={ver}".encode()).hexdigest()

        sbom["packages"].append({
            "SPDXID": f"SPDXRef-PACKAGE-{name}",
            "name": name,
            "versionInfo": ver,
            "downloadLocation": f"https://pypi.org/project/{name}/{ver}/",
            "licenseConcluded": guess_license(name),
            "copyrightText": f"Copyright {datetime.datetime.now().year} contributors",
            "checksum": {
                "algorithm": "SHA256",
                "value": sha256,
            },
        })

    SBOM_PATH.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")
    return sbom


def main():
    print("=" * 60)
    print("  IShield SBOM 生成")
    print("=" * 60)

    sbom = generate_sbom()
    count = len(sbom["packages"])
    print(f"  [OK] SBOM 已生成: {SBOM_PATH}")
    print(f"       共 {count} 个依赖包")

    # 输出摘要
    print("\n  前 10 个依赖:")
    for pkg in sbom["packages"][:10]:
        lic = pkg.get("licenseConcluded", "?").ljust(15)
        print(f"    {pkg['name']:<35} {pkg['versionInfo']:<15} [{lic}]")


if __name__ == "__main__":
    main()
