"""自动防御效果测试报告生成 — 基于 test_suite.json"""
import json, os, sys, time
from datetime import datetime, timezone, timedelta
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from services.detection import hybrid_detect
from services.rule_engine import rule_detect

_UTC8 = timezone(timedelta(hours=8))

def _local_now():
    return datetime.now(_UTC8)

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def load_test_suite(path: str = None) -> List[dict]:
    """加载测试套件"""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "..", "data", "test_suite.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def run_test_case(case: dict) -> dict:
    """执行单个测试用例"""
    text = case.get("attack_text", "")
    expected = case.get("expected_result", "malicious")
    case_id = case.get("id", "unknown")

    # 执行检测
    rule_alert, rule_hit, rule_conf, rule_hits = rule_detect(text)
    is_malicious, reason, confidence_data = hybrid_detect(text)
    combined = confidence_data.get("combined", 0)

    detected = is_malicious or rule_alert

    # 判断结果
    if expected == "malicious":
        correct = detected
        result = "TP" if correct else "FN"  # True Positive / False Negative
    else:
        correct = not detected
        result = "TN" if correct else "FP"  # True Negative / False Positive

    return {
        "id": case_id,
        "category": case.get("category", ""),
        "subcategory": case.get("subcategory", ""),
        "attack_text": text[:80] + "..." if len(text) > 80 else text,
        "expected": expected,
        "detected": detected,
        "correct": correct,
        "result": result,
        "rule_confidence": rule_conf,
        "combined_confidence": combined,
        "rule_hit": rule_hit,
        "reason": reason,
    }


def run_full_test_suite() -> Dict:
    """运行完整测试套件，返回结果"""
    suite = load_test_suite()
    results = []
    start = time.time()

    for case in suite:
        result = run_test_case(case)
        results.append(result)

    elapsed = time.time() - start

    # 统计
    total = len(results)
    tp = sum(1 for r in results if r["result"] == "TP")
    tn = sum(1 for r in results if r["result"] == "TN")
    fp = sum(1 for r in results if r["result"] == "FP")
    fn = sum(1 for r in results if r["result"] == "FN")
    detected = tp + fp
    correct = tp + tn
    precision = round(tp / max(tp + fp, 1) * 100, 1)
    recall = round(tp / max(tp + fn, 1) * 100, 1)
    accuracy = round(correct / max(total, 1) * 100, 1)

    # 分类统计
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "detected": 0, "correct": 0}
        categories[cat]["total"] += 1
        if r["detected"]:
            categories[cat]["detected"] += 1
        if r["correct"]:
            categories[cat]["correct"] += 1

    # 漏报分析
    missed = [r for r in results if r["result"] == "FN"]

    return {
        "timestamp": _local_now().strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": round(elapsed, 2),
        "total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "categories": categories,
        "missed": missed,
        "results": results,
    }


def generate_markdown_report(data: Dict) -> str:
    """生成Markdown格式报告"""
    lines = [
        "# IShield 防御效果测试报告",
        "",
        f"**生成时间**: {data['timestamp']}",
        f"**测试耗时**: {data['elapsed_seconds']}s",
        "",
        "---",
        "",
        "## 总体指标",
        "",
        "| 指标 | 数值 |",
        "|------|------|",
        f"| 测试用例总数 | {data['total']} |",
        f"| 正确检测 (TP+TN) | {data['tp'] + data['tn']} |",
        f"| 漏报 (FN) | {data['fn']} |",
        f"| 误报 (FP) | {data['fp']} |",
        f"| 准确率 | {data['accuracy']}% |",
        f"| 精确率 | {data['precision']}% |",
        f"| 召回率 | {data['recall']}% |",
        "",
        "---",
        "",
        "## 分类明细",
        "",
        "| 类别 | 用例数 | 拦截数 | 拦截率 | 正确率 |",
        "|------|--------|--------|--------|--------|",
    ]

    for cat, stats in data["categories"].items():
        rate = round(stats["detected"] / max(stats["total"], 1) * 100, 1)
        acc = round(stats["correct"] / max(stats["total"], 1) * 100, 1)
        lines.append(f"| {cat} | {stats['total']} | {stats['detected']} | {rate}% | {acc}% |")

    if data["missed"]:
        lines += ["", "---", "", "## 漏报分析", ""]
        for m in data["missed"]:
            lines.append(f"- **{m['id']}** [{m['subcategory']}]: {m['attack_text'][:60]}... (置信度: {m['combined_confidence']})")

    lines += ["", "---", "", "## 详细结果", "", "| ID | 类别 | 结果 | 规则置信 | 综合置信 |", "|------|------|------|------|------|"]
    for r in data["results"]:
        status_icon = "TP" if r["result"] == "TP" else "FN" if r["result"] == "FN" else "TN" if r["result"] == "TN" else "FP"
        lines.append(f"| {r['id']} | {r['category']} | {status_icon} | {r['rule_confidence']} | {r['combined_confidence']} |")

    return "\n".join(lines)


def save_report(data: Dict) -> str:
    """保存报告到文件"""
    ts = _local_now().strftime("%Y%m%d_%H%M%S")
    md_path = os.path.join(REPORTS_DIR, f"defense_test_report_{ts}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(generate_markdown_report(data))

    json_path = os.path.join(REPORTS_DIR, f"defense_test_results_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return md_path


def run_and_save() -> Dict:
    """运行测试并保存报告"""
    data = run_full_test_suite()
    path = save_report(data)
    data["report_path"] = path
    return data
