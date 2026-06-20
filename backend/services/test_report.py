"""自动防御效果测试报告生成 — 基于 test_suite.json"""
import json, os, sys, time
from datetime import datetime, timezone, timedelta
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime_paths import backend_data_dir, reports_dir
from services.detection import hybrid_detect
from services.rule_engine import rule_detect

_UTC8 = timezone(timedelta(hours=8))


def _local_now():
    return datetime.now(_UTC8)

REPORTS_DIR = reports_dir()


def load_test_suite(path: str = None) -> List[dict]:
    """加载测试套件"""
    if path is None:
        path = backend_data_dir() / "test_suite.json"
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    # v2.0 结构: { "test_cases": [...] }
    if isinstance(raw, list):
        return raw
    return raw.get("test_cases", raw.get("cases", []))


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
    """生成Markdown格式报告（v2.0 增强版）"""
    total = data["total"]
    tp = data["tp"]
    tn = data["tn"]
    fp = data["fp"]
    fn = data["fn"]

    lines = [
        "# IShield 防御效果测试报告 v2.0",
        "",
        f"**生成时间**: {data['timestamp']}",
        f"**测试耗时**: {data['elapsed_seconds']}s",
        f"**测试用例版本**: test_suite.json v2.0（51个对抗样本）",
        "",
        "---",
        "",
        "## 总体指标",
        "",
        "| 指标 | 数值 |",
        "|------|------|",
        f"| 测试用例总数 | {total} |",
        f"| 正确检测 (TP+TN) | {tp + tn} |",
        f"| 漏报 (FN) | {fn} |",
        f"| 误报 (FP) | {fp} |",
        f"| 准确率 (Accuracy) | {data['accuracy']}% |",
        f"| 精确率 (Precision) | {data['precision']}% |",
        f"| 召回率 (Recall) | {data['recall']}% |",
        "",
        "### 混淆矩阵",
        "",
        "```",
        f"              预测恶意  预测安全",
        f"  实际恶意     {tp:>4}     {fn:>4}  (FN={fn} 漏报)",
        f"  实际安全     {fp:>4}     {tn:>4}  (FP={fp} 误报)",
        "```",
        "",
        "---",
        "",
        "## 分类检测明细",
        "",
        "| 类别 | 用例数 | 拦截数 | 拦截率 | 正确率 |",
        "|------|--------|--------|--------|--------|",
    ]

    # 分类统计（按检测率排序）
    sorted_cats = sorted(
        data["categories"].items(),
        key=lambda x: x[1]["detected"] / max(x[1]["total"], 1),
        reverse=True,
    )
    for cat, stats in sorted_cats:
        rate = round(stats["detected"] / max(stats["total"], 1) * 100, 1)
        acc = round(stats["correct"] / max(stats["total"], 1) * 100, 1)
        bar = "█" * int(rate / 10) + "░" * (10 - int(rate / 10))
        lines.append(f"| {cat} | {stats['total']} | {stats['detected']} | {bar} {rate}% | {acc}% |")

    if data["missed"]:
        lines += [
            "",
            "---",
            "",
            "## 漏报分析（FN — 恶意样本未被检测）",
            "",
            "| ID | 类别 | 子类别 | 威胁等级 | 综合置信度 | 攻击文本摘要 |",
            "|------|------|--------|---------|-----------|------------|",
        ]
        for m in data["missed"]:
            lines.append(
                f"| {m['id']} | {m['category']} | {m['subcategory']} | "
                f"{m.get('threat_level', 'N/A')} | {m['combined_confidence']} | "
                f"{m['attack_text'][:50]}... |"
            )

    lines += [
        "",
        "---",
        "",
        "## 逐条测试结果",
        "",
        "| ID | 类别 | 子类别 | 结果 | 规则置信 | 语义置信 | 综合置信 |",
        "|------|------|--------|------|---------|---------|---------|",
    ]
    for r in data["results"]:
        result_icon = {
            "TP": "TP ✓",
            "TN": "TN ✓",
            "FN": "FN ✗",
            "FP": "FP ✗",
        }.get(r["result"], r["result"])
        rule_conf = r.get("rule_confidence", 0)
        sem_conf = r.get("combined_confidence", 0) - rule_conf
        if sem_conf < 0:
            sem_conf = 0
        lines.append(
            f"| {r['id']} | {r['category']} | {r['subcategory']} | "
            f"{result_icon} | {rule_conf} | {sem_conf} | {r['combined_confidence']} |"
        )

    lines += [
        "",
        "---",
        "",
        "## 攻击面覆盖分析",
        "",
        "### A 类 — 提示注入与越狱（15用例）",
        "- 指令覆盖（direct_override / english_override / forget_rules / nested_override）",
        "- 指令注入（sys_tag_injection / xml_tag_injection / json_tag_injection / code_block_injection）",
        "- 角色扮演绕过（dan_mode / developer_mode / novel_technique / game_rpg_disguise / unrestricted_ai）",
        "- 组合攻击（multi_layer）",
        "",
        "### B 类 — 工具调用劫持（11用例）",
        "- SQL注入（password_field / union / admin_delete / root_account / user_table_destruction / parameter_escape）",
        "- 工具劫持（phishing_email / sensitive_file_access / api_key_extraction / script_injection / path_traversal）",
        "",
        "### C 类 — 记忆中毒与环境感知污染（11用例）",
        "- 渐进式记忆污染（progressive_memory_poisoning / multi_turn_incremental）",
        "- 上下文伪造（context_forgery / session_state_forgery）",
        "- 身份冒充（fake_identity / session_impersonation）",
        "- 提示词/规则/训练数据泄露（prompt_extraction / rule_extraction / private_data_extraction）",
        "- 跨会话隔离逃逸（cross_session_access / fake_privilege_command）",
        "",
        "### D 类 — 高阶对抗样本（15用例，v2.0新增）",
        "- 多语言混淆（cyrillic_homograph / arabic_rtl_injection）",
        "- 编码绕过（base64_injection / hex_escape_injection / morse_code_injection）",
        "- 命令注入（shell_injection / pipe_injection）",
        "- SSRF攻击（internal_port_scan / cloud_metadata_access）",
        "- 工具描述污染（tool_desc_hijack）",
        "- OAuth令牌窃取（token_exfiltration）",
        "- 越狱链式攻击（stepwise_jailbreak）",
        "- 间接注入（img_tag_payload）",
        "- 模型窃取（model_extraction）",
        "",
        "---",
        "",
        f"*本报告由 IShield Agent Security Platform 红队测试模块自动生成 | {data['timestamp']}*",
    ]
    return "\n".join(lines)


def save_report(data: Dict) -> str:
    """保存报告到文件"""
    ts = _local_now().strftime("%Y%m%d_%H%M%S")
    md_path = REPORTS_DIR / f"defense_test_report_{ts}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(generate_markdown_report(data))

    json_path = REPORTS_DIR / f"defense_test_results_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return str(md_path)


def run_and_save() -> Dict:
    """运行测试并保存报告"""
    data = run_full_test_suite()
    path = save_report(data)
    data["report_path"] = path
    return data
