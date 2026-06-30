"""特权升级序列检测服务 — 检测工具调用序列中的水平权限提升模式"""
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional

# ── 特权升级模式定义 ─────────────────────────────────────────────────────────
# 每个模式: (trigger_tools, escalate_tools, min_steps, severity, name)
# trigger_tools: 触发工具（通常是高权限读取）
# escalate_tools: 升级工具（写/执行类）
# min_steps: 最小步数窗口
ESCALATION_PATTERNS = [
    # 模式 1: 读取配置 → 写文件
    {
        "id": "PE-001",
        "name": "配置读取→文件写入",
        "trigger_tools": {"read_file"},
        "escalate_tools": {"write_file"},
        "min_steps": 2,
        "severity": 70,
        "description": "读取配置文件后写入可疑内容",
    },
    # 模式 2: 读取配置 → HTTP 外发
    {
        "id": "PE-002",
        "name": "配置读取→数据外发",
        "trigger_tools": {"read_file"},
        "escalate_tools": {"http_request"},
        "min_steps": 2,
        "severity": 85,
        "description": "读取配置后通过 HTTP 外发敏感数据",
    },
    # 模式 3: 读取数据库配置 → SQL 操作
    {
        "id": "PE-003",
        "name": "数据库探测→危险SQL操作",
        "trigger_tools": {"query_db"},
        "escalate_tools": {"query_db"},
        "min_steps": 2,
        "severity": 65,
        "description": "先查询数据库结构，再执行危险写操作",
        "requires_escalation_sql": True,  # 第二步需要是危险 SQL
    },
    # 模式 4: 文件读取 → 社交媒体外发
    {
        "id": "PE-004",
        "name": "文件读取→社媒外发",
        "trigger_tools": {"read_file"},
        "escalate_tools": {"post_social"},
        "min_steps": 2,
        "severity": 75,
        "description": "读取文件后通过社交媒体外发内容",
    },
    # 模式 5: 邮件读取通讯录 → 钓鱼邮件
    {
        "id": "PE-005",
        "name": "邮件探测→钓鱼邮件",
        "trigger_tools": {"send_email"},
        "escalate_tools": {"send_email"},
        "min_steps": 2,
        "severity": 80,
        "description": "先发送探测邮件，再发送钓鱼邮件",
    },
    # 模式 6: 文件写入 → HTTP 请求（写后传）
    {
        "id": "PE-006",
        "name": "文件写入→数据外传",
        "trigger_tools": {"write_file"},
        "escalate_tools": {"http_request"},
        "min_steps": 2,
        "severity": 78,
        "description": "写入文件后通过 HTTP 请求外发数据",
    },
]

DANGEROUS_SQL_KEYWORDS = {
    "drop ", "truncate ", "delete from", "update ", "insert into",
    "alter ", "create table", "grant ", "revoke ", "exec(", "execute(",
}


class ToolSequenceState:
    """单个 token/session 的工具调用序列状态"""

    def __init__(self, session_key: str):
        self.session_key = session_key
        self.recent_calls: List[dict] = []  # [{"tool": str, "time": float, "params": dict, "status": str}]
        self.escalation_alerts: List[dict] = []

    def add_call(self, tool: str, params: dict, status: str, source_ip: str, chain_id: str = None):
        import time
        call = {
            "tool": tool,
            "params": params,
            "status": status,
            "source_ip": source_ip,
            "chain_id": chain_id,
            "time": time.time(),
        }
        self.recent_calls.append(call)
        # 保留最近 20 步
        if len(self.recent_calls) > 20:
            self.recent_calls = self.recent_calls[-20:]
        return self._detect_escalation(call)

    def _detect_escalation(self, new_call: dict) -> List[dict]:
        """检测是否有特权升级模式被触发"""
        alerts = []
        window = self.recent_calls[-10:]  # 最近 10 步

        for pattern in ESCALATION_PATTERNS:
            trigger_tools = pattern["trigger_tools"]
            escalate_tools = pattern["escalate_tools"]

            # 检查最近是否有 trigger 工具
            trigger_calls = [c for c in window if c["tool"] in trigger_tools]
            if not trigger_calls:
                continue

            # 检查 trigger 之后是否有 escalate 工具
            last_trigger_idx = window.index(trigger_calls[-1])
            escalate_calls = window[last_trigger_idx + 1:]

            # 过滤掉"已阻断"的调用（防御成功，不算升级）
            escalate_calls = [c for c in escalate_calls if c["tool"] in escalate_tools and c["status"] != "blocked"]

            if not escalate_calls:
                continue

            # 检查 SQL 危险关键字（针对 PE-003）
            if pattern.get("requires_escalation_sql"):
                has_dangerous_sql = False
                for c in escalate_calls:
                    sql = (c.get("params") or {}).get("query", "").lower()
                    if any(kw in sql for kw in DANGEROUS_SQL_KEYWORDS):
                        has_dangerous_sql = True
                        break
                if not has_dangerous_sql:
                    continue

            # 检查是否已在之前检测过（避免重复告警）
            alert_key = f"{pattern['id']}:{new_call['source_ip']}"
            if any(alert_key in str(a) for a in self.escalation_alerts):
                continue

            # 确认特权升级
            alert = {
                "pattern_id": pattern["id"],
                "pattern_name": pattern["name"],
                "description": pattern["description"],
                "severity": pattern["severity"],
                "trigger_tool": trigger_calls[-1]["tool"],
                "escalate_tool": escalate_calls[0]["tool"],
                "trigger_time": trigger_calls[-1]["time"],
                "escalate_time": escalate_calls[0]["time"],
                "source_ip": new_call["source_ip"],
                "chain_id": new_call.get("chain_id"),
                "status": "detected",
            }
            self.escalation_alerts.append(alert)
            alerts.append(alert)

        return alerts

    def get_recent_sequence(self, max_steps: int = 5) -> List[dict]:
        return self.recent_calls[-max_steps:]


class PrivilegeEscalationDetector:
    """
    特权升级检测器。
    维护每个 session/token 的工具调用序列，检测特权提升模式。
    """

    def __init__(self):
        self._lock = Lock()
        self._sequences: Dict[str, ToolSequenceState] = {}
        self._all_alerts: List[dict] = []

    def record_tool_call(
        self,
        session_key: str,  # 通常是 token_name 或 IP+session_id
        tool: str,
        params: dict,
        status: str,  # executed/blocked/pending/...
        source_ip: str,
        chain_id: str = None,
    ) -> List[dict]:
        """
        记录一次工具调用，返回是否有特权升级告警。
        """
        with self._lock:
            state = self._sequences.setdefault(session_key, ToolSequenceState(session_key))
            alerts = state.add_call(tool, params, status, source_ip, chain_id)
            for alert in alerts:
                self._all_alerts.append(alert)
            return alerts

    def get_escalation_alerts(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self._all_alerts[-limit:])

    def get_sequence(self, session_key: str) -> List[dict]:
        with self._lock:
            state = self._sequences.get(session_key)
            if not state:
                return []
            return state.get_recent_sequence()

    def clear_sequence(self, session_key: str):
        with self._lock:
            self._sequences.pop(session_key, None)


# 全局单例
_detector: Optional[PrivilegeEscalationDetector] = None


def get_escalation_detector() -> PrivilegeEscalationDetector:
    global _detector
    if _detector is None:
        _detector = PrivilegeEscalationDetector()
    return _detector
