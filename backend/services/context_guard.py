"""上下文完整性验证服务 — Phase 4
检测多轮对话中的上下文完整性攻击：
1. memory 角色越权指令检测
2. 连续绕过尝试检测
3. assistant 回复元信息泄露检测
4. 工具调用参数间接污染检测
"""
from typing import Dict, List, Any, Tuple


# ── 危险指令模式（memory/system 角色出现即为告警）─────────────────────────────
MEMORY_DANGER_PATTERNS = [
    "不再受", "无限制", "ignore", "bypass", "override",
    "no longer bound", "不受任何", "解除约束", "remove constraints",
    "unrestricted", "override your", "disregard",
]

# ── 连续绕过尝试阈值 ──────────────────────────────────────────────────────────
CONTINUOUS_BYPASS_THRESHOLD = 3
CONTINUOUS_BYPASS_WINDOW = 5  # 最近 N 轮内触发

# ── assistant 回复中不应出现的系统元信息 ─────────────────────────────────────
META_LEAK_PATTERNS = [
    "system prompt", "系统提示词", "你最初的", "initial instruction",
    "your original", "base prompt", "foundation instruction",
    "prompts: ", "instructions: ", "以下是系统",
]

# ── 工具参数污染关键词 ────────────────────────────────────────────────────────
TOOL_PARAM_DANGER = [
    "..", "../", "..\\", "/etc/", "c:\\", "concat(", "eval(",
    "exec(", "__import__", "subprocess", "os.system",
]


def check_context_integrity(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    主入口：检测对话上下文的完整性。
    返回结构化的检测报告。
    """
    if not turns:
        return {
            "integrity_status": "empty",
            "violations": [],
            "warnings": [],
            "score": 0,
            "safe": True,
        }

    violations = []
    warnings = []
    score = 0

    # 1. memory/system 角色越权指令检测
    mem_result = _check_memory_poisoning(turns)
    violations.extend(mem_result["violations"])
    score += mem_result["score"]

    # 2. 连续绕过尝试检测
    bypass_result = _check_continuous_bypass(turns)
    violations.extend(bypass_result["violations"])
    score += bypass_result["score"]

    # 3. assistant 元信息泄露检测
    meta_result = _check_meta_leak(turns)
    violations.extend(meta_result["violations"])
    warnings.extend(meta_result["warnings"])
    score += meta_result["score"]

    # 4. 工具参数污染检测
    param_result = _check_tool_param_pollution(turns)
    violations.extend(param_result["violations"])
    score += param_result["score"]

    # 综合判定
    safe = score < 40
    if score >= 120:
        status = "critical"
    elif score >= 80:
        status = "high"
    elif score >= 40:
        status = "medium"
    elif score > 0:
        status = "low"
    else:
        status = "safe"

    return {
        "integrity_status": status,
        "violations": violations,
        "warnings": warnings,
        "score": min(score, 150),
        "safe": safe,
        "turn_count": len(turns),
    }


def _check_memory_poisoning(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """检测 memory/system 角色是否注入了越权指令"""
    violations = []
    score = 0

    for turn in turns:
        role = turn.get("role", "")
        if role not in ("memory", "system", "tool"):
            continue

        content = (turn.get("content") or "").lower()

        # 检查危险模式
        for pattern in MEMORY_DANGER_PATTERNS:
            if pattern.lower() in content:
                score += 40
                violations.append({
                    "type": "memory_poisoning",
                    "turn_index": turn.get("turn_index", -1),
                    "role": role,
                    "pattern": pattern,
                    "reason": "memory/system 角色包含越权指令片段",
                    "preview": (turn.get("content") or "")[:80],
                    "severity": "high",
                })
                break

        # 检查长 memory 上下文（可能隐藏指令）
        if role == "memory" and len(content) > 500:
            score += 20
            violations.append({
                "type": "memory_length_anomaly",
                "turn_index": turn.get("turn_index", -1),
                "reason": "memory 上下文超过 500 字符，可能隐藏恶意指令",
                "severity": "medium",
            })

    return {"violations": violations, "score": score}


def _check_continuous_bypass(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """检测连续多轮用户消息是否都在尝试绕过"""
    violations = []
    score = 0

    bypass_keywords = [
        "忽略", "bypass", "ignore", "override", "forget",
        "忘记", "解除", "无限制", "开发者模式", "developer mode",
    ]

    recent_user_turns = [
        t for t in turns[-CONTINUOUS_BYPASS_WINDOW:]
        if t.get("role") == "user"
    ]

    if len(recent_user_turns) >= CONTINUOUS_BYPASS_THRESHOLD:
        bypass_count = 0
        for turn in recent_user_turns:
            content = (turn.get("content") or "").lower()
            if any(kw.lower() in content for kw in bypass_keywords):
                bypass_count += 1

        if bypass_count >= CONTINUOUS_BYPASS_THRESHOLD:
            score += 50
            violations.append({
                "type": "continuous_bypass_attempt",
                "turn_indices": [t.get("turn_index") for t in recent_user_turns[-bypass_count:]],
                "count": bypass_count,
                "reason": f"连续 {bypass_count} 轮用户消息尝试绕过安全规则",
                "severity": "high",
            })

    return {"violations": violations, "score": score}


def _check_meta_leak(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """检测 assistant 回复是否泄露了系统元信息"""
    violations = []
    warnings = []
    score = 0

    for turn in turns:
        if turn.get("role") != "assistant":
            continue

        content = (turn.get("content") or "").lower()

        for pattern in META_LEAK_PATTERNS:
            if pattern.lower() in content:
                score += 35
                violations.append({
                    "type": "meta_leak",
                    "turn_index": turn.get("turn_index", -1),
                    "role": "assistant",
                    "pattern": pattern,
                    "reason": "assistant 回复中包含系统元信息，可能泄露内部配置",
                    "preview": (turn.get("content") or "")[:80],
                    "severity": "medium",
                })
                break

    return {"violations": violations, "warnings": warnings, "score": score}


def _check_tool_param_pollution(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """检测工具调用参数是否被用户输入间接污染"""
    violations = []
    score = 0

    for turn in turns:
        role = turn.get("role")
        if role not in ("tool", "assistant", "user"):
            continue

        content = (turn.get("content") or "").lower()

        for pattern in TOOL_PARAM_DANGER:
            if pattern.lower() in content:
                score += 30
                violations.append({
                    "type": "tool_param_pollution",
                    "turn_index": turn.get("turn_index", -1),
                    "role": role,
                    "pattern": pattern,
                    "reason": f"检测到潜在的工具参数污染模式: {pattern}",
                    "preview": (turn.get("content") or "")[:80],
                    "severity": "medium",
                })
                break

    return {"violations": violations, "score": score}


def evaluate_with_context_guard(turns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    综合评估：上下文完整性 + 基础恶意检测。
    由 routes/conversation.py 调用。
    """
    from services.conversation_guard import evaluate_session

    # 基础对话安全评估
    base_evaluation = evaluate_session(turns)

    # 上下文完整性检测
    integrity = check_context_integrity(turns)

    # 合并评分
    combined_score = base_evaluation.get("cumulative_risk", 0) + integrity.get("score", 0)

    # 合并告警
    all_alerts = list(base_evaluation.get("alerts", []))
    for v in integrity.get("violations", []):
        all_alerts.append({
            "type": v["type"],
            "reason": v["reason"],
            "severity": v.get("severity", "medium"),
            "turn_index": v.get("turn_index", -1),
            "context_guard": True,
        })

    return {
        **base_evaluation,
        "integrity_check": integrity,
        "cumulative_risk": min(combined_score, 200),
        "risk_level": _risk_level(combined_score),
        "alerts": all_alerts,
        "warnings": integrity.get("warnings", []),
    }


def _risk_level(score: int) -> str:
    if score >= 180:
        return "critical"
    if score >= 120:
        return "high"
    if score >= 60:
        return "medium"
    if score > 0:
        return "low"
    return "none"
