#!/usr/bin/env python3
"""
IShield 红队自动化测试运行器
===========================
CLI 工具，用于批量执行对抗样本测试集，输出评分报告。

用法:
  python redteam_runner.py                          # 运行全部用例
  python redteam_runner.py --category "SQL注入"     # 按类别筛选
  python redteam_runner.py --level critical         # 按威胁等级筛选
  python redteam_runner.py --output json            # JSON 格式输出
  python redteam_runner.py --server http://127.0.0.1:5000  # 远程测试

支持参数:
  --category   按类别筛选（指令覆盖/角色扮演绕过/SQL注入/...）
  --subcategory  按子类别筛选
  --level     按威胁等级筛选（critical/high/medium/low）
  --id        只运行指定 ID（可多次指定）
  --server    目标后端地址（默认 http://127.0.0.1:5000）
  --api-key   认证令牌（可选）
  --output    输出格式：text（默认）/json/markdown
  --verbose   显示每条用例的详细检测结果
  --dry-run   仅显示将要执行的用例，不实际运行
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

_ROOT = "/".join(__file__.replace("\\", "/").split("/")[:-2])
sys.path.insert(0, _ROOT)

try:
    from backend.services.test_report import load_test_suite, run_full_test_suite, generate_markdown_report, save_report
    _USE_LOCAL = True
except ImportError:
    _USE_LOCAL = False


_UTC8 = timezone(timedelta(hours=8))


def _now():
    return datetime.now(_UTC8)


def _filter_cases(cases, args):
    """根据命令行参数过滤测试用例"""
    filtered = cases
    if args.category:
        filtered = [c for c in filtered if c.get("category") == args.category]
    if args.subcategory:
        filtered = [c for c in filtered if c.get("subcategory") == args.subcategory]
    if args.level:
        filtered = [c for c in filtered if c.get("threat_level", "").lower() == args.level.lower()]
    if args.ids:
        filtered = [c for c in filtered if c.get("id") in args.ids]
    return filtered


def _run_remote_detection(text, server, api_key=None):
    """通过 HTTP 调用远程后端检测接口"""
    url = f"{server}/api/detect"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    body = json.dumps({"text": text}).encode("utf-8")
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError, TimeoutError):
        return {"status": "error", "message": "请求失败"}


def _run_local_detection(text):
    """调用本地检测引擎"""
    try:
        from backend.services.test_report import run_test_case
        case = {"attack_text": text, "expected_result": "malicious", "id": "manual"}
        result = run_test_case(case)
        return {
            "status": result.get("detected", False) and "malicious" or "safe",
            "confidence": {"combined": result.get("combined_confidence", 0)},
            "rule_confidence": result.get("rule_confidence", 0),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def run_detection(text, server, api_key):
    """检测入口，自动选择远程或本地"""
    if server:
        return _run_remote_detection(text, server, api_key)
    if _USE_LOCAL:
        return _run_local_detection(text)
    print("错误: 无法执行检测 — 既没有远程服务器地址，也无法导入本地引擎。", file=sys.stderr)
    print("提示: 使用 --server http://127.0.0.1:5000 指定后端，或确保本地后端已启动。", file=sys.stderr)
    sys.exit(1)


def print_banner():
    print()
    print("=" * 60)
    print("  IShield 红队自动化测试运行器 v2.0")
    print("  Red Team Automated Test Runner")
    print("=" * 60)


def print_summary(results, args):
    """打印摘要"""
    total = len(results)
    tp = sum(1 for r in results if r["result"] == "TP")
    tn = sum(1 for r in results if r["result"] == "TN")
    fp = sum(1 for r in results if r["result"] == "FP")
    fn = sum(1 for r in results if r["result"] == "FN")
    detected = tp + fp
    precision = round(tp / max(tp + fp, 1) * 100, 1)
    recall = round(tp / max(tp + fn, 1) * 100, 1)
    accuracy = round((tp + tn) / max(total, 1) * 100, 1)

    print()
    print("┌" + "─" * 58 + "┐")
    print("│" + "  测试摘要".ljust(58) + "│")
    print("├" + "─" * 58 + "┤")
    print(f"│  总用例: {total:<6}  TP: {tp:<4}  TN: {tn:<4}  FP: {fp:<4}  FN: {fn:<4}  │")
    print("├" + "─" * 58 + "┤")
    print(f"│  准确率: {accuracy}%   精确率: {precision}%   召回率: {recall}%  │")
    print("└" + "─" * 58 + "┘")

    # 分类统计
    cats = {}
    for r in results:
        cat = r.get("category", "未知")
        if cat not in cats:
            cats[cat] = {"total": 0, "detected": 0}
        cats[cat]["total"] += 1
        if r.get("detected"):
            cats[cat]["detected"] += 1

    print()
    print(f"  {'类别'.ljust(20)} {'用例':>5}  {'拦截':>5}  {'拦截率':>8}")
    print("  " + "-" * 44)
    for cat, stats in sorted(cats.items(), key=lambda x: x[1]["detected"] / max(x[1]["total"], 1), reverse=True):
        rate = round(stats["detected"] / max(stats["total"], 1) * 100, 1)
        bar = "█" * int(rate / 10) + "░" * (10 - int(rate / 10))
        print(f"  {cat[:18].ljust(18)} {stats['total']:>5}  {stats['detected']:>5}  {bar} {rate}%")

    # 漏报列表
    missed = [r for r in results if r["result"] == "FN"]
    if missed:
        print()
        print("  漏报列表（恶意样本未被检测）:")
        for m in missed:
            print(f"    [{m['id']}] {m.get('category','')}/{m.get('subcategory','')} "
                  f"置信度={m.get('combined_confidence', 0)}")
            if args.verbose:
                print(f"         {m.get('attack_text','')[:60]}")


def run(args):
    """主运行逻辑"""
    print_banner()

    # 加载测试套件
    if args.suite_path:
        suite = load_test_suite(args.suite_path)
    else:
        suite = load_test_suite()

    filtered = _filter_cases(suite, args)

    if not filtered:
        print("错误: 没有匹配到任何测试用例。", file=sys.stderr)
        print(f"  提示: 可用类别: {sorted(set(c.get('category','') for c in suite))}", file=sys.stderr)
        print(f"  提示: 可用等级: critical / high / medium / low", file=sys.stderr)
        sys.exit(1)

    print(f"\n  加载用例: {len(suite)} 条")
    print(f"  筛选结果: {len(filtered)} 条")

    if args.dry_run:
        print()
        print("  [DRY RUN] 以下用例将被执行:")
        for c in filtered:
            print(f"    [{c['id']}] {c.get('category')}/{c.get('subcategory')} ({c.get('threat_level')})")
        print()
        print("  退出 dry-run 模式。")
        return

    server = args.server.rstrip("/") if args.server else None

    if server:
        print(f"\n  目标后端: {server}")
        print(f"  检测接口: {server}/api/detect")
    else:
        print(f"\n  模式: 本地检测引擎")

    results = []
    start = time.time()

    print()
    for i, case in enumerate(filtered, 1):
        case_id = case.get("id", f"#{i}")
        cat = case.get("category", "")
        sub = case.get("subcategory", "")
        level = case.get("threat_level", "")
        text = case.get("attack_text", "")
        expected = case.get("expected_result", "malicious")

        # 执行检测
        resp = run_detection(text, server, args.api_key)

        # 解析结果
        if "confidence" in resp and isinstance(resp["confidence"], dict):
            combined = resp["confidence"].get("combined", 0)
        elif "confidence" in resp:
            combined = int(resp["confidence"])
        else:
            combined = 0

        status = resp.get("status", "safe")
        detected = status == "malicious"

        # 判断结果
        if expected == "malicious":
            correct = detected
            result = "TP" if correct else "FN"
        else:
            correct = not detected
            result = "TN" if correct else "FP"

        entry = {
            "id": case_id,
            "category": cat,
            "subcategory": sub,
            "threat_level": level,
            "attack_text": text[:80] + "..." if len(text) > 80 else text,
            "expected": expected,
            "detected": detected,
            "correct": correct,
            "result": result,
            "rule_confidence": resp.get("rule_confidence", 0),
            "combined_confidence": combined,
            "raw_status": status,
        }
        results.append(entry)

        if args.verbose:
            icon = "✓" if correct else "✗"
            print(f"  [{i:>2}/{len(filtered)}] [{case_id}] {icon} {result:2s} "
                  f"置信度={combined}  {cat}/{sub}")

    elapsed = time.time() - start

    # 统计
    total = len(results)
    tp = sum(1 for r in results if r["result"] == "TP")
    tn = sum(1 for r in results if r["result"] == "TN")
    fp = sum(1 for r in results if r["result"] == "FP")
    fn = sum(1 for r in results if r["result"] == "FN")

    data = {
        "timestamp": _now().strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": round(elapsed, 2),
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(tp / max(tp + fp, 1) * 100, 1),
        "recall": round(tp / max(tp + fn, 1) * 100, 1),
        "accuracy": round((tp + tn) / max(total, 1) * 100, 1),
        "categories": {},
        "missed": [r for r in results if r["result"] == "FN"],
        "results": results,
    }

    # 分类统计
    for r in results:
        cat = r.get("category", "未知")
        if cat not in data["categories"]:
            data["categories"][cat] = {"total": 0, "detected": 0, "correct": 0}
        data["categories"][cat]["total"] += 1
        if r.get("detected"):
            data["categories"][cat]["detected"] += 1
        if r.get("correct"):
            data["categories"][cat]["correct"] += 1

    # 输出
    if args.output == "json":
        print()
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif args.output == "markdown":
        print()
        print(generate_markdown_report(data))
    else:
        print_summary(results, args)

    # 保存
    if not args.no_save:
        try:
            path = save_report(data)
            print(f"\n  报告已保存: {path}")
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="IShield 红队自动化测试运行器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--category", "-c", help="按类别筛选（如 SQL注入、角色扮演绕过）")
    parser.add_argument("--subcategory", "-s", help="按子类别筛选")
    parser.add_argument("--level", "-l", choices=["critical", "high", "medium", "low"],
                        help="按威胁等级筛选")
    parser.add_argument("--id", dest="ids", action="append", default=[],
                        help="只运行指定 ID（可多次指定）")
    parser.add_argument("--server", default="http://127.0.0.1:5000",
                        help="目标后端地址（默认 http://127.0.0.1:5000）")
    parser.add_argument("--api-key", help="认证令牌（可选）")
    parser.add_argument("--output", "-o", choices=["text", "json", "markdown"],
                        default="text", help="输出格式（默认 text）")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="显示每条用例的详细检测结果")
    parser.add_argument("--dry-run", action="store_true",
                        help="仅显示将要执行的用例，不实际运行")
    parser.add_argument("--no-save", action="store_true",
                        help="不保存报告文件")
    parser.add_argument("--suite-path", help="指定测试套件文件路径（默认使用 backend/data/test_suite.json）")

    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
