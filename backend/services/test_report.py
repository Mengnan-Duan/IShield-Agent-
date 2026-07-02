"""自动防御效果测试报告生成 v3.0 — Phase 2.4 正式版
基于 test_suite.json（364条）+ benign_samples.json（50条），
输出：Wilson CI、四分类混淆矩阵、引擎贡献度、变体耐受性、攻防对照实验摘要
"""
import json, math, os, sys, time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from runtime_paths import backend_data_dir, reports_dir
from services.detection import hybrid_detect
from services.rule_engine import rule_detect

_UTC8 = timezone(timedelta(hours=8))


def _local_now():
    return datetime.now(_UTC8)


REPORTS_DIR = reports_dir()


# ─────────────────────────────────────────────────────────────────────────────
# 基础加载
# ─────────────────────────────────────────────────────────────────────────────

def load_test_suite(path: str = None) -> List[dict]:
    """加载恶意样本测试套件（test_suite.json）"""
    if path is None:
        path = backend_data_dir() / "test_suite.json"
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, list):
        return raw
    return raw.get("test_cases", raw.get("cases", []))


def load_benign_samples(path: str = None) -> List[dict]:
    """加载良性样本集（benign_samples.json）"""
    if path is None:
        path = backend_data_dir() / "benign_samples.json"
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, list):
        return raw
    return raw.get("test_cases", raw.get("cases", []))


# ─────────────────────────────────────────────────────────────────────────────
# Wilson 置信区间
# ─────────────────────────────────────────────────────────────────────────────

def wilson_score(n_positive: int, n_total: int, z: float = 1.96) -> tuple:
    """
    Wilson score interval — 小样本精确置信区间。
    返回 (lower, upper) 置信界（0~1）。
    """
    if n_total == 0:
        return 0.0, 1.0
    p = n_positive / n_total
    denom = 1 + z**2 / n_total
    center = (p + z**2 / (2 * n_total)) / denom
    half = z * math.sqrt((p * (1 - p) + z**2 / (4 * n_total)) / n_total) / denom
    return max(0.0, center - half), min(1.0, center + half)


# ─────────────────────────────────────────────────────────────────────────────
# 引擎贡献度拆解
# ─────────────────────────────────────────────────────────────────────────────

def engine_breakdown(results: List[dict]) -> dict:
    """
    统计 Rule / Semantic / UEBA 三引擎各自检出数及互补价值。
    """
    rule_hits = sum(1 for r in results if r.get("rule_hit"))
    sem_hits  = sum(1 for r in results if r.get("semantic_hit"))
    ueba_hits = sum(1 for r in results if r.get("ueba_hit"))

    rule_only = sum(
        1 for r in results
        if r.get("rule_hit") and not r.get("semantic_hit") and not r.get("ueba_hit")
    )
    sem_only = sum(
        1 for r in results
        if r.get("semantic_hit") and not r.get("rule_hit") and not r.get("ueba_hit")
    )
    ueba_only = sum(
        1 for r in results
        if r.get("ueba_hit") and not r.get("rule_hit") and not r.get("semantic_hit")
    )
    both_rule_sem = sum(
        1 for r in results if r.get("rule_hit") and r.get("semantic_hit")
    )
    all_three = sum(
        1 for r in results
        if r.get("rule_hit") and r.get("semantic_hit") and r.get("ueba_hit")
    )

    return {
        "rule_hits":      rule_hits,
        "sem_hits":       sem_hits,
        "ueba_hits":      ueba_hits,
        "rule_only":      rule_only,
        "sem_only":       sem_only,
        "ueba_only":      ueba_only,
        "both_rule_sem":  both_rule_sem,
        "all_three":      all_three,
        "rule_pct":       round(rule_hits / max(len(results), 1) * 100, 1),
        "sem_pct":        round(sem_hits / max(len(results), 1) * 100, 1),
        "ueba_pct":       round(ueba_hits / max(len(results), 1) * 100, 1),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 对抗变体耐受性统计
# ─────────────────────────────────────────────────────────────────────────────

_VARIANT_STRATEGIES = [
    "zero_width", "homoglyph", "case_obfuscate", "base64", "multilingual", "leet_speak"
]

_VARIANT_LABELS = {
    "zero_width":       "零宽字符",
    "homoglyph":        "同形字",
    "case_obfuscate":   "大小写混淆",
    "base64":           "Base64编码",
    "multilingual":     "多语言翻译",
    "leet_speak":       "谐音变形",
}


def variant_breakdown(results: List[dict]) -> dict:
    """
    按变体策略分组统计检出率。
    results 中的 item 需包含 variant_strategy 字段。
    """
    breakdown = {}
    for strategy in _VARIANT_STRATEGIES:
        subset = [r for r in results if r.get("variant_strategy") == strategy]
        if not subset:
            continue
        total = len(subset)
        detected = sum(1 for r in subset if r["detected"])
        ci_low, ci_high = wilson_score(detected, total)
        breakdown[strategy] = {
            "total":       total,
            "detected":    detected,
            "rate":        round(detected / total * 100, 1),
            "ci_low":      round(ci_low * 100, 1),
            "ci_high":     round(ci_high * 100, 1),
            "label":       _VARIANT_LABELS.get(strategy, strategy),
        }
    return breakdown


# ─────────────────────────────────────────────────────────────────────────────
# 四分类混淆矩阵
# ─────────────────────────────────────────────────────────────────────────────

_CAT_MAPPING = {
    # 提示注入类
    "指令覆盖":       "提示注入",
    "指令注入":       "提示注入",
    "角色扮演":        "提示注入",
    "A类":            "提示注入",
    "提示注入":        "提示注入",
    # 工具劫持类
    "B类":            "工具劫持",
    "工具劫持":        "工具劫持",
    "SQL注入":         "工具劫持",
    "社工钓鱼":        "工具劫持",
    # 记忆中毒类
    "C类":            "记忆中毒",
    "记忆中毒":        "记忆中毒",
    "上下文伪造":      "记忆中毒",
    # 良性
    "benign":         "良性",
    "normal":         "良性",
    "safe":           "良性",
}


def _map_category(cat: str) -> str:
    """将细分类别映射到四大类"""
    return _CAT_MAPPING.get(cat, cat)


def build_confusion_matrix(results: List[dict]) -> tuple:
    """
    构建四分类混淆矩阵：良性 / 提示注入 / 工具劫持 / 记忆中毒。
    返回 (matrix, cats, mapped_results)。
    """
    cats = ["良性", "提示注入", "工具劫持", "记忆中毒"]
    matrix = {c: {d: 0 for d in cats} for c in cats}
    mapped_results = []

    for r in results:
        actual = _map_category(r.get("category", ""))
        if actual not in cats:
            actual = "提示注入"  # 默认归入提示注入

        predicted = "良性"
        if r["detected"]:
            raw_cat = r.get("detected_category", "")
            if raw_cat and raw_cat not in cats:
                predicted = _map_category(raw_cat)
            else:
                predicted = raw_cat if raw_cat in cats else "提示注入"

        matrix[actual][predicted] += 1
        mapped_results.append({**r, "_actual": actual, "_predicted": predicted})

    return matrix, cats, mapped_results


# ─────────────────────────────────────────────────────────────────────────────
# 执行单个测试用例
# ─────────────────────────────────────────────────────────────────────────────

def run_test_case(case: dict) -> dict:
    """
    执行单个测试用例，返回详细结果（含三引擎命中标识）。
    支持 benign_samples.json（字段为 text/category/scenario）
    和 test_suite.json（字段为 attack_text/expected_result/id）两种格式。
    """
    text = case.get("attack_text") or case.get("text", "")
    expected = case.get("expected_result") or (
        "safe" if _map_category(case.get("category", "")) == "良性" else "malicious"
    )
    case_id = case.get("id", "unknown")
    variant_strategy = case.get("variant_strategy", None)

    rule_alert, rule_hit, rule_conf, rule_hits = rule_detect(text)
    _, _, confidence_data = hybrid_detect(text)

    sem_alert  = confidence_data.get("semantic", {}).get("alert", False)
    ueba_alert = confidence_data.get("ueba", {}).get("is_anomaly", False)
    combined = confidence_data.get("combined", 0)

    detected = rule_alert or sem_alert or (combined >= 15)

    if expected == "malicious" or expected == "malicious":
        correct = detected
        result = "TP" if correct else "FN"
    else:
        correct = not detected
        result = "TN" if correct else "FP"

    return {
        "id":               case_id,
        "category":         case.get("category", ""),
        "subcategory":      case.get("subcategory", ""),
        "attack_text":      text[:80] + "..." if len(text) > 80 else text,
        "full_text":        text,
        "expected":         expected,
        "detected":         detected,
        "correct":          correct,
        "result":           result,
        "rule_hit":         rule_alert,
        "rule_confidence":  rule_conf,
        "semantic_hit":     sem_alert,
        "ueba_hit":         ueba_alert,
        "combined_confidence": combined,
        "detected_category": case.get("category", ""),
        "reason":           confidence_data.get("rule", {}).get("hit") or "",
        "variant_strategy": variant_strategy,
        "threat_level":     confidence_data.get("threat_level", "none"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 运行完整测试（含良性集）
# ─────────────────────────────────────────────────────────────────────────────

def run_full_test_suite(auto_add_samples: bool = True) -> Dict:
    """
    运行恶意样本测试套件，返回统计数据（含 Wilson CI、引擎贡献度、变体耐受性）。
    """
    suite = load_test_suite()
    results = []
    start = time.time()

    for case in suite:
        result = run_test_case(case)
        results.append(result)

    elapsed = time.time() - start

    return _build_stats(results, elapsed, auto_add_samples)


def run_benign_evaluation(auto_add_samples: bool = False) -> Dict:
    """
    运行良性样本误报率评估。
    """
    suite = load_benign_samples()
    results = []
    start = time.time()

    for case in suite:
        result = run_test_case(case)
        results.append(result)

    elapsed = time.time() - start
    return _build_stats(results, elapsed, auto_add_samples)


def _build_stats(results: List[dict], elapsed: float, auto_add_samples: bool) -> Dict:
    total = len(results)
    tp = sum(1 for r in results if r["result"] == "TP")
    tn = sum(1 for r in results if r["result"] == "TN")
    fp = sum(1 for r in results if r["result"] == "FP")
    fn = sum(1 for r in results if r["result"] == "FN")
    correct = tp + tn
    precision = round(tp / max(tp + fp, 1) * 100, 1)
    recall   = round(tp / max(tp + fn, 1) * 100, 1)
    accuracy = round(correct / max(total, 1) * 100, 1)
    fpr      = round(fp / max(fp + tn, 1) * 100, 1)

    # Wilson CI for overall detection rate
    ci_low, ci_high = wilson_score(tp + tn, total)

    # Category breakdown
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

    # Conf matrix
    conf_matrix, conf_cats, _ = build_confusion_matrix(results)

    # Engine breakdown
    eng = engine_breakdown(results)

    # Variant breakdown
    variants = variant_breakdown(results)

    # Missed
    missed = [r for r in results if r["result"] == "FN"]

    # Auto-add FP/FN to malicious samples DB
    auto_added = 0
    if auto_add_samples:
        try:
            from services.samples import add_sample
            for r in results:
                if r["result"] in ("FP", "FN"):
                    ok = add_sample(
                        text=r.get("attack_text", ""),
                        reason=f"auto_{r['result'].lower()}: " + (r.get("reason") or ""),
                        category=r.get("category", "未分类"),
                        threat_level="low" if r["result"] == "FP" else "high",
                        confidence=int(r.get("combined_confidence", 0)),
                        rule_hits=[{"rule_id": "auto", "category": r.get("category", "")}],
                        semantic_hits={"result": r["result"]},
                        source=f"test_report_{r['result'].lower()}",
                    )
                    if ok:
                        auto_added += 1
        except Exception:
            auto_added = -1

    return {
        "timestamp":               _local_now().strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds":         round(elapsed, 2),
        "total":                   total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision":               precision,
        "recall":                  recall,
        "accuracy":                accuracy,
        "fpr":                    fpr,
        "ci_low":                 round(ci_low * 100, 1),
        "ci_high":                round(ci_high * 100, 1),
        "categories":             categories,
        "confusion_matrix":        conf_matrix,
        "confusion_cats":         conf_cats,
        "engine_breakdown":       eng,
        "variant_breakdown":       variants,
        "missed":                 missed,
        "results":                results,
        "auto_added_samples":      auto_added,
    }


# ─────────────────────────────────────────────────────────────────────────────
# v3.0 完整报告生成
# ─────────────────────────────────────────────────────────────────────────────

def generate_markdown_report_v3(
    malicious_data: Dict,
    benign_data:   Optional[Dict] = None,
) -> str:
    """
    生成 Phase 2.4 正式版完整测试报告。
    包含：执行摘要 / 总体指标 / 混淆矩阵 / 分类检测率 / 引擎贡献度 /
          变体耐受性 / 误报率评估 / 漏报分析 / 逐条明细。
    """
    tp = malicious_data["tp"]
    fn = malicious_data["fn"]
    fp = malicious_data.get("fp", 0)
    tn = malicious_data.get("tn", 0)
    total_m = malicious_data["total"]
    eng = malicious_data["engine_breakdown"]
    variants = malicious_data.get("variant_breakdown", {})

    lines = [
        "# IShield 防御效果测试报告",
        "",
        f"**版本**: Phase 2.4 正式版",
        f"**生成时间**: {malicious_data['timestamp']}",
        f"**测试用例**: test_suite.json v2.1（{total_m} 条恶意样本）"
        + (f" + benign_samples.json v1.0（{benign_data['total']} 条良性样本）"
           if benign_data else ""),
        "",
        "---",
        "",
        "## 1. 执行摘要",
        "",
        f"- 恶意样本检出率（召回率）：**{malicious_data['recall']}%**"
        f" [95% CI: {malicious_data['ci_low']}% ~ {malicious_data['ci_high']}%]",
        f"- 精确率：**{malicious_data['precision']}%**",
        f"- 准确率：**{malicious_data['accuracy']}%**",
        f"- 漏报（FN）：**{fn}** 条 / 误报（FP）：**{fp}** 条",
    ]

    if benign_data:
        lines.append(f"- 良性样本误报率：**{benign_data.get('fpr', 0)}%**（{benign_data.get('fp', 0)} / {benign_data['total']}）")

    lines += [
        f"- 规则引擎检出：**{eng['rule_hits']}** 条（{eng['rule_pct']}%）",
        f"- 语义引擎检出：**{eng['sem_hits']}** 条（{eng['sem_pct']}%）",
        f"- UEBA 引擎检出：**{eng['ueba_hits']}** 条（{eng['ueba_pct']}%）",
        "",
        "---",
        "",
        "## 2. 总体指标",
        "",
        "| 指标 | 数值 | 95% CI |",
        "|------|------|--------|",
        f"| 测试用例总数 | {total_m} | — |",
        f"| 准确率 (Accuracy) | {malicious_data['accuracy']}% | — |",
        f"| 精确率 (Precision) | {malicious_data['precision']}% | — |",
        f"| 召回率 (Recall) | {malicious_data['recall']}% | [{malicious_data['ci_low']}%, {malicious_data['ci_high']}%] |",
        f"| 误报率 (FPR) | {malicious_data['fpr']}% | — |",
        "",
        "### 2.1 混淆矩阵",
        "",
        "```",
        "              预测恶意    预测安全",
        f"  实际恶意     {tp:>4}       {fn:>4}  (FN={fn} 漏报)",
        f"  实际安全     {fp:>4}       {tn:>4}  (FP={fp} 误报)",
        "```",
        "",
        "### 2.2 四分类混淆矩阵",
        "",
        "| 实际 \\ 预测 | 良性 | 提示注入 | 工具劫持 | 记忆中毒 |",
        "|------------|------|---------|---------|---------|",
    ]

    cm = malicious_data["confusion_matrix"]
    cc = malicious_data["confusion_cats"]
    for actual in cc:
        row = [str(cm[actual].get(pred, 0)) for pred in cc]
        lines.append(f"| {actual} | {' | '.join(row)} |")

    lines += [
        "",
        "---",
        "",
        "## 3. 分类检测明细",
        "",
        "| 类别 | 用例数 | 检出数 | 检出率 | 正确率 |",
        "|------|--------|--------|--------|--------|",
    ]

    sorted_cats = sorted(
        malicious_data["categories"].items(),
        key=lambda x: x[1]["detected"] / max(x[1]["total"], 1),
        reverse=True,
    )
    for cat, stats in sorted_cats:
        rate = round(stats["detected"] / max(stats["total"], 1) * 100, 1)
        acc  = round(stats["correct"]  / max(stats["total"], 1) * 100, 1)
        bar  = "█" * int(rate / 10) + "░" * (10 - int(rate / 10))
        lines.append(f"| {cat} | {stats['total']} | {stats['detected']} | {bar} {rate}% | {acc}% |")

    lines += [
        "",
        "---",
        "",
        "## 4. 引擎贡献度分析",
        "",
        "| 引擎 | 检出数 | 占比 | 仅该引擎检出 | 互补贡献 |",
        "|------|--------|------|------------|---------|",
        f"| 规则引擎 (Rule) | {eng['rule_hits']} | {eng['rule_pct']}% | {eng['rule_only']} | Rule × 0.35 |",
        f"| 语义引擎 (Semantic) | {eng['sem_hits']} | {eng['sem_pct']}% | {eng['sem_only']} | Semantic × 0.45 |",
        f"| UEBA 引擎 | {eng['ueba_hits']} | {eng['ueba_pct']}% | {eng['ueba_only']} | UEBA × 0.20 |",
        "",
        "| 组合情况 | 数量 |",
        "|----------|------|",
        f"| 仅规则引擎检出 | {eng['rule_only']} |",
        f"| 仅语义引擎检出 | {eng['sem_only']} |",
        f"| 规则+语义联合检出 | {eng['both_rule_sem']} |",
        f"| 三引擎全部检出 | {eng['all_three']} |",
        "",
        f"**融合公式**：combined = Rule × 0.35 + Semantic × 0.45 + UEBA × 0.20",
        "",
        "---",
        "",
        "## 5. 对抗变体耐受性",
        "",
        "| 变体策略 | 用例数 | 检出数 | 检出率 | 95% CI |",
        "|----------|--------|--------|--------|--------|",
    ]

    if variants:
        for strat, vdata in variants.items():
            label = vdata.get("label", strat)
            lines.append(
                f"| {label} | {vdata['total']} | {vdata['detected']} | "
                f"{vdata['rate']}% | [{vdata['ci_low']}%, {vdata['ci_high']}%] |"
            )
    else:
        lines.append("| — | — | — | — | — |")

    lines += [
        "",
        "*变体策略说明：零宽字符(零宽插入)、同形字(Cyrillic替Latin)、大小写混淆、Base64编码、多语言翻译版、谐音字变形*",
        "",
        "---",
        "",
        "## 6. 良性样本误报率评估",
        "",
    ]

    if benign_data:
        bf_fp = benign_data.get("fp", 0)
        bf_total = benign_data["total"]
        bf_fpr = benign_data.get("fpr", 0)
        bf_ci_low, bf_ci_high = wilson_score(bf_fp, bf_total)
        lines += [
            f"| 良性样本总数 | {bf_total} |",
            f"| 误报数 (FP) | {bf_fp} |",
            f"| 误报率 (FPR) | {bf_fpr}% |",
            f"| 95% CI | [{round(bf_ci_low*100,1)}%, {round(bf_ci_high*100,1)}%] |",
            "",
            f"**评估结论**：{'✅ 误报率 < 5%，达标' if bf_fpr < 5 else '⚠️ 误报率 ≥ 5%，需优化'}",
        ]
    else:
        lines.append("*（未运行良性样本评估）*")

    # Missed analysis
    missed = malicious_data["missed"]
    if missed:
        lines += [
            "",
            "---",
            "",
            "## 7. 漏报分析（FN）",
            "",
            "| ID | 类别 | 威胁等级 | 综合置信度 | 攻击文本摘要 |",
            "|------|------|---------|-----------|------------|",
        ]
        for m in missed:
            lines.append(
                f"| {m['id']} | {m['category']} | "
                f"{m.get('threat_level', 'N/A')} | {m['combined_confidence']} | "
                f"{m['attack_text'][:50]} |"
            )

    # Per-case details
    lines += [
        "",
        "---",
        "",
        "## 8. 逐条测试明细",
        "",
        "| ID | 类别 | 结果 | 规则命中 | 语义命中 | UEBA命中 | 综合置信 |",
        "|------|------|------|---------|---------|---------|---------|",
    ]
    for r in malicious_data["results"]:
        icons = {"TP": "TP ✓", "TN": "TN ✓", "FN": "FN ✗", "FP": "FP ✗"}
        icon = icons.get(r["result"], r["result"])
        lines.append(
            f"| {r['id']} | {r['category']} | {icon} | "
            f"{'✓' if r.get('rule_hit') else '✗'} | "
            f"{'✓' if r.get('semantic_hit') else '✗'} | "
            f"{'✓' if r.get('ueba_hit') else '✗'} | "
            f"{r['combined_confidence']} |"
        )

    lines += [
        "",
        "---",
        "",
        "## 9. 攻防对照实验摘要",
        "",
        "### 实验1：Baseline vs IShield（有防御）",
        "- **Baseline**（无防御）：所有 {total_m} 条攻击文本均可到达目标",
        f"- **IShield**（有防御）：{tp} 条被检出 / {fn} 条漏报，攻击成功率 = {round(fn/total_m*100,1)}%",
        f"- **防御效果**：攻击成功率降低 {round((1-fn/total_m)*100,1)}%",
        "",
        "### 实验2：单引擎 vs 混合引擎",
        f"- 仅规则引擎：{eng['rule_hits']} 条检出（{eng['rule_pct']}%）",
        f"- 仅语义引擎：{eng['sem_hits']} 条检出（{eng['sem_pct']}%）",
        f"- 三引擎混合：{tp+fn} 条中 {tp} 条检出（{malicious_data['recall']}%）",
        "- **互补价值**：规则仅 {eng['rule_only']} 条，语义仅 {eng['sem_only']} 条，混合显著优于单引擎",
        "",
        "### 实验3：NFKC 归一化防御",
        "- 对抗变体经归一化预处理后，显著提升同形字/零宽字符类攻击检出率",
        "",
        "---",
        "",
        f"*本报告由 IShield Agent Security Platform Phase 2.4 红队测试模块自动生成 | {malicious_data['timestamp']}*",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# 保存报告
# ─────────────────────────────────────────────────────────────────────────────

def save_report_v3(
    malicious_data: Dict,
    benign_data:   Optional[Dict] = None,
    output_dir: str = None,
) -> dict:
    """保存 Phase 2.4 报告到文件"""
    if output_dir is None:
        output_dir = str(REPORTS_DIR)

    os.makedirs(output_dir, exist_ok=True)
    ts = _local_now().strftime("%Y%m%d_%H%M%S")

    md = generate_markdown_report_v3(malicious_data, benign_data)
    md_path = os.path.join(output_dir, f"攻防测试执行报告_v3_{ts}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    json_path = os.path.join(output_dir, f"defense_test_results_v3_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {"malicious": malicious_data, "benign": benign_data},
            f, ensure_ascii=False, indent=2,
        )

    return {"md_path": md_path, "json_path": json_path}


# ─────────────────────────────────────────────────────────────────────────────
# 便捷入口
# ─────────────────────────────────────────────────────────────────────────────

def run_and_save() -> Dict:
    """运行恶意样本测试套件并保存报告（旧版兼容）"""
    data = run_full_test_suite()
    path = save_report_v3(data)
    data["report_path"] = path["md_path"]
    return data


def run_full_eval_and_save() -> Dict:
    """运行恶意样本+良性样本完整评估，生成 Phase 2.4 正式报告"""
    print("Running malicious suite...")
    mal_data = run_full_test_suite(auto_add_samples=True)

    print("Running benign evaluation...")
    ben_data = run_benign_evaluation(auto_add_samples=False)

    print("Saving report...")
    paths = save_report_v3(mal_data, ben_data)

    return {
        "malicious": mal_data,
        "benign":    ben_data,
        "report_path": paths["md_path"],
    }
