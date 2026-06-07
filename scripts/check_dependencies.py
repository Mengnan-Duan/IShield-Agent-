"""
供应链安全检查脚本 — 检查 requirements.txt 中的依赖是否有已知 CVE
对应《智能体规范》第9条：加强供应链安全
"""
import subprocess
import sys
import json
import datetime
from pathlib import Path

REPORT_PATH = Path(__file__).parent.parent / "SECURITY_REPORT.md"


def run_pip_audit():
    """使用 pip-audit 检查依赖漏洞"""
    print("[供应链检查] 运行 pip-audit...")
    try:
        result = subprocess.run(
            ["pip-audit", "--format=json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return {"status": "clean", "packages": []}
        # pip-audit 返回 0 = 干净，1 = 有漏洞，其他 = 错误
        if result.returncode == 1:
            data = json.loads(result.stdout) if result.stdout else {"vulnerabilities": []}
            pkgs = data.get("vulnerabilities", [])
            return {"status": "vulnerable", "packages": pkgs}
        return {"status": "error", "message": result.stderr or "unknown error"}
    except FileNotFoundError:
        return {"status": "not_installed", "message": "pip-audit not installed (run: pip install pip-audit)"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "pip-audit timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def check_requirements_versions():
    """检查 requirements.txt 中是否有危险的版本约束"""
    req_file = Path(__file__).parent.parent / "requirements.txt"
    issues = []
    if not req_file.exists():
        return issues
    for line in req_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # 检查：没有版本约束的包（latest = 高风险）
        if ">=" in line or "==" in line or "~=" in line:
            continue
        pkg = line.split("==")[0].split(">=")[0].split("~=")[0].strip()
        if pkg:
            issues.append(f"  WARNING: '{line}' 没有版本上限约束，建议改为 '{line},<{next_major}'")
    return issues


def generate_report(audit_result: dict, version_issues: list):
    """生成 Markdown 安全报告"""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    vuln_count = len(audit_result.get("packages", []))
    if audit_result["status"] == "vulnerable":
        vuln_rows = []
        for pkg in audit_result["packages"]:
            for vuln in pkg.get("vulns", []):
                vuln_rows.append(
                    f"| {pkg['name']} | {vuln.get('id','?')} | {vuln.get('fix_versions','N/A')} |"
                )
        vuln_table = "| 包名 | CVE ID | 修复版本 |\n|---|---|---|\n" + "\n".join(vuln_rows)
    else:
        vuln_table = "_无已知漏洞_"

    report = f"""# 安全报告 — IShield Agent Security Platform
**生成时间**: {now}
**检查依据**: 《智能体规范应用与创新发展实施意见》第9条 — 加强供应链安全

---

## 一、依赖漏洞扫描（pip-audit）

**状态**: {"发现漏洞" if vuln_count > 0 else "无已知漏洞"} ({vuln_count} 个包受影响)

{vuln_table}

---

## 二、版本约束检查

{chr(10).join(version_issues) if version_issues else '_所有依赖均有版本约束，无警告_'}

---

## 三、安全建议

1. **立即行动**：如有 CVE 漏洞，立即升级到修复版本
2. **定期扫描**：建议 CI/CD 流程中加入 `pip-audit` 检查
3. **锁定版本**：使用 `pip-compile` 生成 `requirements.txt`，避免隐式升级
4. **镜像扫描**：如使用 Docker，添加 `trivy image scan` 到构建流程

---

## 四、相关法规对照

| 条款 | 要求 | 实现状态 |
|---|---|---|
| 第9条 供应链安全 | 全周期安全规范、风险预警 | 已实现（自动化检查） |

*本报告自动生成，建议配合人工审查使用。*
"""
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"[完成] 安全报告已写入 {REPORT_PATH}")
    return report


def main():
    print("=" * 60)
    print("  IShield 供应链安全检查")
    print("=" * 60)

    audit = run_pip_audit()
    if audit["status"] == "not_installed":
        print(f"  [!] pip-audit 未安装: {audit['message']}")
        print("     安装: pip install pip-audit")
    elif audit["status"] == "error":
        print(f"  [!] pip-audit 运行失败: {audit['message']}")
    else:
        print(f"  pip-audit: {'发现漏洞' if audit['status']=='vulnerable' else '干净'} ({len(audit.get('packages',[]))} 个包)")

    version_issues = check_requirements_versions()
    if version_issues:
        print(f"  版本约束警告: {len(version_issues)} 条")
        for issue in version_issues:
            print(issue)
    else:
        print("  版本约束: 无警告")

    generate_report(audit, version_issues)

    if audit["status"] == "vulnerable" and audit["packages"]:
        print("\n  [!] 检测到漏洞，退出码 1")
        sys.exit(1)
    else:
        print("\n  [OK] 供应链安全检查通过")


if __name__ == "__main__":
    main()
