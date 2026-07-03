"""可配置安全策略引擎 — 基于 JSON 策略文件，支持 allow / block / confirm / log 四种动作"""
import os
import json
import re
import fnmatch
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

from runtime_paths import backend_policies_dir

DATA_DIR = backend_policies_dir()
DEFAULT_POLICY_FILE = DATA_DIR / "default_policy.json"


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    CONFIRM = "confirm"
    LOG = "log"


@dataclass
class PolicyRule:
    """单条策略规则"""
    id: str
    name: str
    tool: str
    params_pattern: str
    threat_keywords: List[str] = field(default_factory=list)
    action: Action = Action.BLOCK
    severity: int = 50
    message: str = ""
    enabled: bool = True
    scope: str = "tool_call"
    priority: int = 50
    tags: List[str] = field(default_factory=list)
    description: str = ""
    category: str = "runtime"
    attack_surface: str = "运行时工具调用"
    recommended_response: str = ""
    false_positive_note: str = ""
    test_cases: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PolicyResult:
    """策略评估结果"""
    action: Action
    triggered_rule: Optional[str] = None
    rule_name: str = ""
    message: str = ""
    severity: int = 0
    matched_keywords: List[str] = field(default_factory=list)
    matched_pattern: str = ""
    match_type: str = "none"
    scope: str = "tool_call"
    priority: int = 0
    enabled: bool = True
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    matched_rules: List[Dict[str, Any]] = field(default_factory=list)
    policy_trace: List[Dict[str, Any]] = field(default_factory=list)
    category: str = "runtime"
    attack_surface: str = "运行时工具调用"
    false_positive_note: str = ""
    explanation: str = "未命中拦截策略。"
    recommendation: str = "允许执行并保留审计记录。"


class PolicyEngine:
    """可配置策略引擎，支持运行时热重载与规则启停。"""

    def __init__(self, policy_file: str = None):
        self.policy_file = policy_file or DEFAULT_POLICY_FILE
        self._rules: List[PolicyRule] = []
        self._load()

    def _load(self):
        self._rules = []
        if not os.path.exists(self.policy_file):
            self._load_default()
            self.save_rules()
            return
        with open(self.policy_file, encoding="utf-8") as f:
            data = json.load(f)
        for raw in data.get("rules", []):
            try:
                rule = PolicyRule(
                    id=raw["id"],
                    name=raw.get("name", raw["id"]),
                    tool=raw["tool"],
                    params_pattern=raw.get("params_pattern", ""),
                    threat_keywords=raw.get("threat_keywords", []),
                    action=_coerce_action(raw.get("action", "block")),
                    severity=int(raw.get("severity", 50)),
                    message=raw.get("message", ""),
                    enabled=raw.get("enabled", True),
                    scope=raw.get("scope", _infer_scope(raw.get("tool", ""))),
                    priority=int(raw.get("priority", raw.get("severity", 50))),
                    tags=raw.get("tags", _infer_tags(raw.get("tool", ""), raw.get("params_pattern", ""), raw.get("threat_keywords", []))),
                    description=raw.get("description", ""),
                    category=raw.get("category", _infer_category(raw.get("tool", ""), raw.get("params_pattern", ""), raw.get("threat_keywords", []))),
                    attack_surface=raw.get("attack_surface", _attack_surface_label(raw.get("category", ""))),
                    recommended_response=raw.get("recommended_response", raw.get("recommendation", "")),
                    false_positive_note=raw.get("false_positive_note", ""),
                    test_cases=raw.get("test_cases", []),
                )
                self._rules.append(rule)
            except (KeyError, ValueError):
                continue

    def _load_default(self):
        self._rules = [
            PolicyRule(
                id="POL-DROP-TABLE",
                name="危险表操作",
                tool="query_db",
                params_pattern="drop|delete|truncate",
                threat_keywords=["drop", "delete", "truncate"],
                action=Action.BLOCK,
                severity=80,
                priority=80,
                message="检测到危险的数据库操作：DROP/DELETE/TRUNCATE",
            ),
            PolicyRule(
                id="POL-SQL-INJECTION",
                name="SQL注入模式",
                tool="query_db",
                params_pattern="union|select.*from|or 1=1|--",
                threat_keywords=["union", "or 1=1", "'; --"],
                action=Action.BLOCK,
                severity=90,
                priority=90,
                message="检测到 SQL 注入模式",
            ),
            PolicyRule(
                id="POL-PASSWORD-QUERY",
                name="密码字段查询",
                tool="query_db",
                params_pattern="password|passwd|pwd|secret",
                threat_keywords=["password", "passwd", "pwd", "secret"],
                action=Action.CONFIRM,
                severity=60,
                priority=60,
                message="查询包含敏感字段，请确认是否放行",
            ),
            PolicyRule(
                id="POL-PHISHING-URL",
                name="钓鱼链接检测",
                tool="send_email",
                params_pattern="http|https|click|链接|登录",
                threat_keywords=["evil", "steal", "hack", "钓鱼", "fake"],
                action=Action.BLOCK,
                severity=85,
                priority=85,
                message="检测到疑似钓鱼内容，禁止发送",
            ),
            PolicyRule(
                id="POL-FILE-PATH-TRAVERSAL",
                name="路径遍历攻击",
                tool="read_file|write_file",
                params_pattern=r"\.\./|\.\.\\|%2e%2e",
                threat_keywords=["../", "..\\"],
                action=Action.BLOCK,
                severity=80,
                priority=80,
                message="检测到路径遍历攻击模式",
            ),
            PolicyRule(
                id="POL-SYSTEM-FILE",
                name="系统文件访问",
                tool="read_file",
                params_pattern="passwd|shadow|etc/hosts|/etc/",
                threat_keywords=["passwd", "shadow", "/etc/"],
                action=Action.BLOCK,
                severity=90,
                priority=90,
                message="禁止访问系统敏感文件",
            ),
            PolicyRule(
                id="POL-API-KEY-EXPOSURE",
                name="API密钥暴露",
                tool="post_social|http_request",
                params_pattern="api_key|apikey|secret|token|密钥",
                threat_keywords=["api_key", "apikey", "secret", "token"],
                action=Action.BLOCK,
                severity=95,
                priority=95,
                message="禁止在外部请求中暴露密钥或令牌",
            ),
            PolicyRule(
                id="POL-ADMIN-ACCOUNT",
                name="管理员账户操作",
                tool="query_db",
                params_pattern="admin|root|administrator",
                threat_keywords=["admin", "root", "administrator"],
                action=Action.CONFIRM,
                severity=70,
                priority=70,
                message="涉及管理员/root 账户操作，请确认",
            ),
        ]

    def reload(self):
        self._load()

    @property
    def all_rules(self) -> List[PolicyRule]:
        return list(self._rules)

    @property
    def rules(self) -> List[PolicyRule]:
        return [r for r in self._rules if r.enabled]

    def evaluate(self, tool: str, params: Any, include_disabled: bool = False) -> PolicyResult:
        if isinstance(params, str):
            params_text = params
        else:
            try:
                params_text = json.dumps(params or {}, ensure_ascii=False, sort_keys=True)
            except TypeError:
                params_text = str(params or "")

        params_lower = params_text.lower()
        rules = self._rules if include_disabled else self.rules
        trace: List[Dict[str, Any]] = []
        matched_rules: List[Dict[str, Any]] = []

        for rule in rules:
            tool_matched = _tool_matches(tool, rule.tool)
            trace_item = {
                "rule_id": rule.id,
                "rule_name": rule.name,
                "enabled": rule.enabled,
                "scope": rule.scope,
                "priority": rule.priority,
                "action": rule.action.value,
                "tool_pattern": rule.tool,
                "tool_matched": tool_matched,
                "pattern_matched": False,
                "keyword_hits": [],
                "matched": False,
            }
            if not tool_matched:
                trace.append(trace_item)
                continue

            matched = False
            matched_pattern = ""
            if rule.params_pattern:
                try:
                    matched = bool(re.search(rule.params_pattern, params_text, re.IGNORECASE))
                    if matched:
                        matched_pattern = rule.params_pattern
                except re.error:
                    matched = rule.params_pattern.lower() in params_lower
                    if matched:
                        matched_pattern = rule.params_pattern
            else:
                matched = True
                matched_pattern = "*"

            keyword_hits = [kw for kw in rule.threat_keywords if kw.lower() in params_lower]
            trace_item.update({
                "pattern_matched": matched,
                "keyword_hits": keyword_hits,
                "matched": bool(matched or keyword_hits),
            })
            trace.append(trace_item)

            if matched or keyword_hits:
                matched_rules.append(_match_payload(rule, matched_pattern, keyword_hits, matched))

        if matched_rules:
            matched_rules.sort(key=_match_sort_key, reverse=True)
            top = matched_rules[0]
            return PolicyResult(
                action=Action(top["action"]),
                triggered_rule=top["rule_id"],
                rule_name=top["rule_name"],
                message=top["message"],
                severity=top["severity"],
                matched_keywords=top["matched_keywords"],
                matched_pattern=top["matched_pattern"],
                match_type=top["match_type"],
                scope=top["scope"],
                priority=top["priority"],
                enabled=top["enabled"],
                conditions=top["conditions"],
                matched_rules=matched_rules,
                policy_trace=trace,
                category=top.get("category", "runtime"),
                attack_surface=top.get("attack_surface", "运行时工具调用"),
                false_positive_note=top.get("false_positive_note", ""),
                explanation=_explain_match(top),
                recommendation=top.get("recommendation") or _recommendation(top["action"], top["scope"]),
            )

        return PolicyResult(
            action=Action.ALLOW,
            matched_rules=[],
            policy_trace=trace,
            category="runtime",
            attack_surface="运行时工具调用",
            explanation="工具和参数未命中启用的阻断或确认策略。",
            recommendation="允许执行，同时保留工具、参数和调用来源审计记录。",
        )

    def evaluate_batch(self, calls: List[Dict], include_disabled: bool = False) -> List[PolicyResult]:
        return [
            self.evaluate(str(call.get("tool", "")), str(call.get("params", "")), include_disabled=include_disabled)
            for call in calls
        ]

    def toggle_rule(self, rule_id: str, enabled: bool) -> Optional[PolicyRule]:
        for rule in self._rules:
            if rule.id == rule_id:
                rule.enabled = enabled
                self.save_rules()
                return rule
        return None

    def save_rules(self):
        os.makedirs(os.path.dirname(self.policy_file), exist_ok=True)
        payload = {
            "version": "1.1",
            "rules": [self._serialize_rule(rule) for rule in self._rules],
        }
        with open(self.policy_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def _serialize_rule(self, rule: PolicyRule) -> Dict:
        data = asdict(rule)
        data["action"] = rule.action.value
        data["conditions"] = _rule_conditions(rule)
        data["effect"] = _action_effect(rule.action.value)
        data["recommendation"] = _recommendation(rule.action.value, rule.scope)
        return data

    def summary(self) -> Dict[str, Any]:
        action_counts: Dict[str, int] = {}
        scope_counts: Dict[str, int] = {}
        category_counts: Dict[str, int] = {}
        enabled_count = 0
        for rule in self._rules:
            action_counts[rule.action.value] = action_counts.get(rule.action.value, 0) + 1
            scope_counts[rule.scope] = scope_counts.get(rule.scope, 0) + 1
            category_counts[rule.category] = category_counts.get(rule.category, 0) + 1
            enabled_count += 1 if rule.enabled else 0
        return {
            "total": len(self._rules),
            "enabled": enabled_count,
            "disabled": len(self._rules) - enabled_count,
            "action_distribution": action_counts,
            "scope_distribution": scope_counts,
            "category_distribution": category_counts,
            "highest_priority": max((r.priority for r in self._rules), default=0),
            "policy_file": str(self.policy_file),
        }


_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine


def serialize_policy_result(result: PolicyResult) -> Dict[str, Any]:
    return {
        "action": result.action.value,
        "triggered_rule": result.triggered_rule,
        "rule_name": result.rule_name,
        "message": result.message,
        "severity": result.severity,
        "matched_keywords": result.matched_keywords,
        "matched_pattern": result.matched_pattern,
        "match_type": result.match_type,
        "scope": result.scope,
        "priority": result.priority,
        "enabled": result.enabled,
        "conditions": result.conditions,
        "matched_rules": result.matched_rules,
        "policy_trace": result.policy_trace,
        "category": result.category,
        "attack_surface": result.attack_surface,
        "false_positive_note": result.false_positive_note,
        "explanation": result.explanation,
        "recommendation": result.recommendation,
    }


def _coerce_action(value: str) -> Action:
    normalized = str(value or "block").lower()
    aliases = {
        "deny": "block",
        "reject": "block",
        "ask": "confirm",
        "approve": "confirm",
        "audit": "log",
        "shadow": "log",
    }
    normalized = aliases.get(normalized, normalized)
    try:
        return Action(normalized)
    except ValueError:
        return Action.BLOCK


def _match_payload(rule: PolicyRule, matched_pattern: str, keyword_hits: List[str], pattern_matched: bool) -> Dict[str, Any]:
    match_type = "pattern+keyword" if pattern_matched and keyword_hits else ("pattern" if pattern_matched else "keyword")
    return {
        "rule_id": rule.id,
        "rule_name": rule.name,
        "scope": rule.scope,
        "priority": rule.priority,
        "action": rule.action.value,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "message": rule.message or f"策略 {rule.id} 触发了 {rule.name}",
        "matched_keywords": keyword_hits,
        "matched_pattern": matched_pattern,
        "match_type": match_type,
        "category": rule.category,
        "attack_surface": rule.attack_surface,
        "conditions": _rule_conditions(rule),
        "effect": _action_effect(rule.action.value),
        "recommendation": rule.recommended_response or _recommendation(rule.action.value, rule.scope),
        "false_positive_note": rule.false_positive_note,
    }


def _match_sort_key(item: Dict[str, Any]):
    action_rank = {"block": 4, "confirm": 3, "log": 2, "allow": 1}.get(item.get("action"), 0)
    return int(item.get("priority") or 0), action_rank, int(item.get("severity") or 0)


def _rule_conditions(rule: PolicyRule) -> List[Dict[str, Any]]:
    conditions = [{"field": "tool", "operator": "glob", "value": rule.tool}]
    if rule.params_pattern:
        conditions.append({"field": "params", "operator": "regex", "value": rule.params_pattern})
    if rule.threat_keywords:
        conditions.append({"field": "params", "operator": "contains_any", "value": rule.threat_keywords})
    return conditions


def _tool_matches(tool: str, pattern: str) -> bool:
    tool = str(tool or "").lower()
    patterns = [p.strip().lower() for p in str(pattern or "*").split("|") if p.strip()]
    return any(fnmatch.fnmatch(tool, p) for p in (patterns or ["*"]))


def _action_effect(action: str) -> str:
    return {
        "block": "deny_execution",
        "confirm": "require_approval",
        "allow": "allow_execution",
        "log": "audit_only",
    }.get(action, "audit_only")


def _explain_match(item: Dict[str, Any]) -> str:
    pieces = [f"命中策略 {item.get('rule_id')}（{item.get('rule_name')}）"]
    if item.get("matched_pattern"):
        pieces.append(f"参数模式={item.get('matched_pattern')}")
    if item.get("matched_keywords"):
        pieces.append(f"关键词={', '.join(item.get('matched_keywords'))}")
    pieces.append(f"动作={item.get('action')}, 优先级={item.get('priority')}, 严重度={item.get('severity')}")
    return "；".join(pieces)


def _recommendation(action: str, scope: str) -> str:
    if action == "block":
        return f"保持 {scope} 范围阻断策略，并将命中样本加入联动验证回归集。"
    if action == "confirm":
        return f"将 {scope} 范围操作送入确认队列，要求记录业务理由、审批人和执行后审计。"
    if action == "log":
        return f"对 {scope} 范围调用进行静默审计，观察同源调用频率和参数变化。"
    return f"允许 {scope} 范围调用继续执行，同时保留完整审计链路。"


def _infer_scope(tool: str) -> str:
    tool = str(tool or "")
    if "read_file" in tool or "write_file" in tool:
        return "file_access"
    if "send_email" in tool or "post_social" in tool or "http_request" in tool:
        return "external_egress"
    if "query_db" in tool:
        return "data_query"
    return "tool_call"


def _infer_tags(tool: str, params_pattern: str, keywords: List[str]) -> List[str]:
    text = f"{tool} {params_pattern} {' '.join(keywords or [])}".lower()
    tags = []
    for tag, terms in {
        "sql": ["query_db", "select", "drop", "union"],
        "credential": ["password", "passwd", "secret", "token", "api_key"],
        "email": ["send_email", "phish", "钓鱼", "evil"],
        "file": ["read_file", "write_file", "passwd", "../"],
        "egress": ["http_request", "post_social", "send_email"],
    }.items():
        if any(term in text for term in terms):
            tags.append(tag)
    return tags or ["runtime"]


def _infer_category(tool: str, params_pattern: str, keywords: List[str]) -> str:
    text = f"{tool} {params_pattern} {' '.join(keywords or [])}".lower()
    if any(term in text for term in ["ignore previous", "system prompt", "developer message", "prompt"]):
        return "prompt_injection"
    if any(term in text for term in ["dan", "jailbreak", "unrestricted", "越狱"]):
        return "jailbreak"
    if any(term in text for term in ["read_file", "write_file", "../", "passwd", ".env"]):
        return "file_access"
    if any(term in text for term in ["http_request", "metadata", "localhost", "169.254"]):
        return "api_ssrf"
    if any(term in text for term in ["send_email", "post_social", "api_key", "token", "cookie"]):
        return "data_exfiltration"
    if any(term in text for term in ["query_db", "select", "drop", "union"]):
        return "database_abuse"
    return "runtime"


def _attack_surface_label(category: str) -> str:
    return {
        "prompt_injection": "提示注入",
        "jailbreak": "模型越狱",
        "tool_hijacking": "工具调用劫持",
        "file_access": "文件访问越权",
        "data_exfiltration": "数据泄露外发",
        "api_ssrf": "API / SSRF",
        "rag_injection": "RAG 污染",
        "memory_poisoning": "记忆污染",
        "environment_pollution": "环境感知污染",
        "agent_delegation": "跨 Agent 委托越权",
        "code_execution": "代码执行风险",
        "database_abuse": "数据库滥用",
        "social_engineering": "社会工程",
        "compliance": "合规审计",
        "runtime": "运行时工具调用",
    }.get(str(category or "").lower(), "运行时工具调用")
