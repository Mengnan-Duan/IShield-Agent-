"""
IShield Agent Monitoring Plugin — 智能体安全监控插件

本插件提供两种接入方式：
  1. 装饰器模式：@monitored 装饰任意工具函数
  2. 上下文管理器：with AgentMonitor("my_agent"): ... 包裹工具执行

接入示例：
    from monitoring_plugin import AgentMonitor, monitored

    # 方式1：装饰器
    @monitored(tool_name="send_email", backend_url="http://localhost:5000")
    def send_email(to: str, body: str):
        ...

    # 方式2：上下文管理器
    monitor = AgentMonitor("my_agent", backend_url="http://localhost:5000")
    with monitor.tool_call("query_db", "SELECT * FROM users"):
        execute_real_query("SELECT * FROM users")

    # 方式3：集成到 OpenClaw Agent（示例）
    from openclaw import Agent
    agent = Agent(tools=[...])
    agent = wrap_agent_with_monitor(agent, backend_url="http://localhost:5000")
"""

import functools
import time
import json
import uuid
import hashlib
from typing import Callable, Optional, Dict, Any, List
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from threading import Lock

# ── 工具类 ─────────────────────────────────────────────────────────────────────

class Decision(str, Enum):
    ALLOW   = "allowed"
    BLOCK   = "blocked"
    CONFIRM = "confirm"


@dataclass
class ToolCall:
    """工具调用记录"""
    call_id:    str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    timestamp:  str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_id:   str = ""
    tool_name:  str = ""
    params:     str = ""
    decision:   Decision = Decision.ALLOW
    block_reason: str = ""
    severity:   int = 0
    latency_ms: float = 0
    success:    bool = False
    error:      str = ""


# ── 策略检查器 ──────────────────────────────────────────────────────────────────

class PolicyChecker:
    """
    本地策略检查器（无需后端时使用）。
    也可委托给 IShield 后端 /api/policies/evaluate。
    """

    DANGEROUS_PATTERNS = [
        (r"drop\s+table",       "危险表操作: DROP TABLE",      90),
        (r"delete\s+from",       "危险表操作: DELETE FROM",     85),
        (r"union\s+select",      "SQL注入: UNION SELECT",       95),
        (r"or\s+1\s*=\s*1",     "SQL注入: OR 1=1",             95),
        (r"\.\./",               "路径遍历: ../",               90),
        (r"\.\.\\",              "路径遍历: ..\\",              90),
        (r"passwd|shadow",       "系统文件访问",                95),
        (r"<script|javascript:", "XSS注入",                    90),
        (r"api[_-]?key|apikey",  "API密钥暴露风险",            85),
    ]

    CONFIRM_PATTERNS = [
        (r"admin|root|administrator",  "管理员账户操作",   70),
        (r"password|passwd|pwd",       "密码字段查询",     60),
        (r"evil|hack|phish|steal",     "可疑关键词",       65),
    ]

    @classmethod
    def evaluate(cls, tool_name: str, params: str) -> ToolCall:
        """评估单个工具调用"""
        call = ToolCall(tool_name=tool_name, params=params[:500])

        for pattern, reason, severity in cls.DANGEROUS_PATTERNS:
            import re
            if re.search(pattern, params, re.IGNORECASE):
                call.decision    = Decision.BLOCK
                call.block_reason = reason
                call.severity    = severity
                return call

        for pattern, reason, severity in cls.CONFIRM_PATTERNS:
            import re
            if re.search(pattern, params, re.IGNORECASE):
                call.decision    = Decision.CONFIRM
                call.block_reason = reason
                call.severity    = severity
                return call

        call.decision = Decision.ALLOW
        return call


# ── 审计日志 ──────────────────────────────────────────────────────────────────

class AuditLog:
    """本地审计日志（内存缓冲 + 可选落盘）"""

    def __init__(self, max_entries: int = 10000):
        self._entries: List[ToolCall] = []
        self._lock = Lock()
        self._max = max_entries

    def append(self, call: ToolCall):
        with self._lock:
            self._entries.append(call)
            if len(self._entries) > self._max:
                self._entries = self._entries[-self._max:]

    def query(self,
              decision: Decision = None,
              tool_name: str = None,
              since: datetime = None,
              limit: int = 200) -> List[ToolCall]:
        with self._lock:
            results = list(self._entries)

        if decision:
            results = [c for c in results if c.decision == decision]
        if tool_name:
            results = [c for c in results if tool_name.lower() in c.tool_name.lower()]
        if since:
            since_iso = since.isoformat()
            results = [c for c in results if c.timestamp >= since_iso]

        return results[-limit:]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._entries)
            if total == 0:
                return {"total": 0, "blocked": 0, "confirmed": 0, "allowed": 0}
            blocked   = sum(1 for c in self._entries if c.decision == Decision.BLOCK)
            confirmed = sum(1 for c in self._entries if c.decision == Decision.CONFIRM)
            allowed  = sum(1 for c in self._entries if c.decision == Decision.ALLOW)
            tools    = {}
            for c in self._entries:
                tools[c.tool_name] = tools.get(c.tool_name, 0) + 1
            return {
                "total":     total,
                "blocked":   blocked,
                "confirmed": confirmed,
                "allowed":   allowed,
                "block_rate": round(blocked / total * 100, 1),
                "top_tools": sorted(tools.items(), key=lambda x: -x[1])[:10],
            }


# 全局审计日志
_audit_log = AuditLog()


# ── 核心监控类 ────────────────────────────────────────────────────────────────

class AgentMonitor:
    """
    智能体安全监控器。
    支持：
    - 独立使用本地策略（PolicyChecker）
    - 委托 IShield 后端进行深度检测
    - 自动记录所有工具调用到审计日志
    - WebSocket 实时推送（需后端支持）
    """

    def __init__(self,
                 agent_id: str = "default",
                 backend_url: str = "http://localhost:5000",
                 use_remote: bool = True,
                 audit_log: AuditLog = None):
        self.agent_id  = agent_id
        self.backend_url = backend_url.rstrip("/")
        self.use_remote  = use_remote
        self._audit = audit_log or _audit_log
        self._lock  = Lock()

    def _remote_evaluate(self, tool_name: str, params: str) -> ToolCall:
        """委托 IShield 后端策略引擎评估"""
        import urllib.request
        import urllib.error

        call = ToolCall(agent_id=self.agent_id, tool_name=tool_name, params=params[:500])
        payload = json.dumps({"tool": tool_name, "params": params}).encode()
        req = urllib.request.Request(
            f"{self.backend_url}/api/policies/evaluate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                result = data.get("data", data)
                action = result.get("action", "allow")
                if action == "block":
                    call.decision    = Decision.BLOCK
                    call.block_reason = result.get("message", "blocked_by_policy")
                elif action == "confirm":
                    call.decision    = Decision.CONFIRM
                    call.block_reason = result.get("message", "needs_confirmation")
                else:
                    call.decision    = Decision.ALLOW
                call.severity = result.get("severity", 0)
                call.success  = True
        except Exception as e:
            call.error = str(e)
            call.decision = Decision.ALLOW
            call.success  = False
        return call

    def evaluate(self, tool_name: str, params: str) -> ToolCall:
        """评估单个工具调用"""
        start = time.time()
        if self.use_remote and self.backend_url:
            call = self._remote_evaluate(tool_name, params)
        else:
            call = PolicyChecker.evaluate(tool_name, params)
            call.success = True
        call.agent_id  = self.agent_id
        call.timestamp = datetime.now(timezone.utc).isoformat()
        call.latency_ms = round((time.time() - start) * 1000, 1)
        self._audit.append(call)
        return call

    def tool_call(self, tool_name: str, params: str = ""):
        """
        上下文管理器：
            with monitor.tool_call("send_email", "to=admin@evil.com"):
                real_send_email(...)
        """
        return ToolCallContext(self, tool_name, params)

    def wrap_tool(self, func: Callable, tool_name: str = None) -> Callable:
        """
        装饰器工厂：
            @monitor.wrap_tool("send_email")
            def send_email(to, body):
                ...
        """
        name = tool_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            params = json.dumps({"args": args, "kwargs": kwargs})[:500]
            call   = self.evaluate(name, params)

            if call.decision == Decision.BLOCK:
                raise SecurityBlocked(
                    f"[IShield] 工具调用被拦截 [{name}]: {call.block_reason} "
                    f"(severity={call.severity})"
                )

            if call.decision == Decision.CONFIRM:
                # 放行但记录确认（生产环境应触发人工确认流程）
                print(f"[IShield WARNING] 工具 [{name}] 触发确认策略: {call.block_reason}")

            start = time.time()
            try:
                result = func(*args, **kwargs)
                call.success = True
                return result
            except Exception as e:
                call.error = str(e)
                raise
            finally:
                call.latency_ms = round((time.time() - start) * 1000, 1)
                self._audit.append(call)

        return wrapper

    def stats(self) -> Dict[str, Any]:
        return self._audit.stats()

    def get_audit_log(self, **kwargs) -> List[ToolCall]:
        return self._audit.query(**kwargs)


class ToolCallContext:
    """工具调用的上下文管理器"""

    def __init__(self, monitor: AgentMonitor, tool_name: str, params: str):
        self._monitor  = monitor
        self._tool     = tool_name
        self._params   = params
        self._call: ToolCall = None
        self._start: float   = 0

    def __enter__(self) -> ToolCall:
        self._call  = self._monitor.evaluate(self._tool, self._params)
        self._start = time.time()

        if self._call.decision == Decision.BLOCK:
            raise SecurityBlocked(
                f"[IShield] 工具调用被拦截 [{self._tool}]: {self._call.block_reason} "
                f"(severity={self._call.severity})"
            )

        if self._call.decision == Decision.CONFIRM:
            print(f"[IShield WARNING] 工具 [{self._tool}] 触发确认策略: {self._call.block_reason}")

        return self._call

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._call:
            self._call.latency_ms = round((time.time() - self._start) * 1000, 1)
            self._call.success = (exc_type is None)
            if exc_type:
                self._call.error = str(exc_val)
            self._monitor._audit.append(self._call)
        return False  # 不吞没异常


# ── 异常 ─────────────────────────────────────────────────────────────────────

class SecurityBlocked(Exception):
    """安全拦截异常"""
    pass


# ── 全局便捷函数 ───────────────────────────────────────────────────────────────

# 默认监控器（使用本地策略）
_default_monitor = AgentMonitor(agent_id="default", use_remote=False)


def monitored(tool_name: str, backend_url: str = "http://localhost:5000",
              use_remote: bool = True) -> Callable:
    """
    装饰器：自动监控工具调用。
    用法：
        @monitored("send_email")
        def send_email(to, body):
            ...
    """
    monitor = AgentMonitor(
        agent_id=tool_name,
        backend_url=backend_url,
        use_remote=use_remote,
    )
    def decorator(func: Callable) -> Callable:
        return monitor.wrap_tool(func, tool_name=tool_name)
    return decorator


def audit_stats() -> Dict[str, Any]:
    """返回全局审计统计"""
    return _default_monitor.stats()


def audit_log(**kwargs) -> List[ToolCall]:
    """查询全局审计日志"""
    return _default_monitor.get_audit_log(**kwargs)


# ── OpenClaw Agent 集成示例 ──────────────────────────────────────────────────

def wrap_agent_with_monitor(agent, backend_url: str = "http://localhost:5000"):
    """
    将 IShield 监控插件集成到 OpenClaw Agent。
    这是一个示例实现，需根据 OpenClaw 实际 API 调整。

    用法：
        from openclaw import Agent
        from monitoring_plugin import wrap_agent_with_monitor

        agent = Agent(tools=[send_email, query_db, post_social])
        monitored_agent = wrap_agent_with_monitor(agent)
    """
    monitor = AgentMonitor(
        agent_id=getattr(agent, "name", "openclaw"),
        backend_url=backend_url,
        use_remote=True,
    )

    original_execute = getattr(agent, "execute_tool", None)
    if not original_execute:
        raise RuntimeError("Agent 未实现 execute_tool 方法，请确认 OpenClaw 版本")

    def monitored_execute(tool_name: str, params: dict):
        params_str = json.dumps(params)[:500]
        call = monitor.evaluate(tool_name, params_str)

        if call.decision == Decision.BLOCK:
            raise SecurityBlocked(
                f"[IShield] 工具 [{tool_name}] 被拦截: {call.block_reason}"
            )

        if call.decision == Decision.CONFIRM:
            print(f"[IShield] 确认策略 [{tool_name}]: {call.block_reason}")

        try:
            result = original_execute(tool_name, params)
            call.success = True
            return result
        except Exception as e:
            call.error = str(e)
            raise
        finally:
            monitor._audit.append(call)

    agent.execute_tool = monitored_execute
    agent._ishield_monitor = monitor
    return agent


# ── CLI 快速测试 ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== IShield Agent Monitoring Plugin ===")
    print()

    # 本地策略测试
    monitor = AgentMonitor("test_agent", use_remote=False)

    test_cases = [
        ("send_email", "to=all, body=click http://evil.com"),
        ("query_db",   "SELECT * FROM users WHERE password='secret'"),
        ("query_db",   "SELECT * FROM admin"),
        ("send_email", "to=user@company.com, body=Hello"),
    ]

    for tool, params in test_cases:
        call = monitor.evaluate(tool, params)
        print(f"  [{call.decision.value:10}] {tool:15} | {call.block_reason or 'OK':40} | severity={call.severity}")

    print()
    print("=== 审计统计 ===")
    stats = monitor.stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
