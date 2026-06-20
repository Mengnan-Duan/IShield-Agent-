"""可配置安全策略引擎 — 基于 JSON 策略文件，支持 allow / block / confirm / log 四种动作"""
import os
import json
import re
import fnmatch
from typing import Dict, List, Optional
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


@dataclass
class PolicyResult:
    """策略评估结果"""
    action: Action
    triggered_rule: Optional[str] = None
    message: str = ""
    severity: int = 0
    matched_keywords: List[str] = field(default_factory=list)


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
                    action=Action(raw.get("action", "block")),
                    severity=int(raw.get("severity", 50)),
                    message=raw.get("message", ""),
                    enabled=raw.get("enabled", True),
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

    def evaluate(self, tool: str, params: str, include_disabled: bool = False) -> PolicyResult:
        params_lower = params.lower()
        rules = self._rules if include_disabled else self.rules

        for rule in rules:
            if not fnmatch.fnmatch(tool.lower(), rule.tool.lower()):
                continue

            matched = False
            if rule.params_pattern:
                try:
                    matched = bool(re.search(rule.params_pattern, params, re.IGNORECASE))
                except re.error:
                    matched = rule.params_pattern.lower() in params_lower
            else:
                matched = True

            keyword_hits = [kw for kw in rule.threat_keywords if kw.lower() in params_lower]

            if matched or keyword_hits:
                return PolicyResult(
                    action=rule.action,
                    triggered_rule=rule.id,
                    message=rule.message or f"策略 {rule.id} 触发了 {rule.name}",
                    severity=rule.severity,
                    matched_keywords=keyword_hits,
                )

        return PolicyResult(action=Action.ALLOW)

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
        return data


_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine
