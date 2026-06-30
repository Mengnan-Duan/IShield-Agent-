"""
IShield OpenClaw Agent 接入适配器
=================================
将外部开源 Agent（如 OpenClaw）的工具调用纳入 IShield 监控范围。

工作原理：
  外部 Agent 的所有工具调用通过本适配器代理执行，
  调用链：Agent → openclaw_adapter → hybrid_detect → PolicyEngine → ToolRunner → 沙箱

使用方式：
  from tools.openclaw_adapter import AgentMonitor
  monitor = AgentMonitor(agent_id="openclaw-01", agent_name="OpenClaw Demo")
  monitor.register()
  # 之后 Agent 所有工具调用通过 monitor.execute_tool() 执行

外部 Agent 示例：
  from tools.openclaw_adapter import create_openclaw_proxy
  proxy = create_openclaw_proxy(agent_id="test-agent")
  result = proxy.read_file(path="/etc/passwd")
"""

import sys
import os
import json
import time
import uuid
import threading
from typing import Any, Dict, List, Optional, Callable
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.detection import hybrid_detect
from services.policy import PolicyEngine
from services.behavior_analyzer import BehaviorAnalyzer
from services.websocket import broadcast_event, broadcast_alert
from services.events import add_event
from tools.tool_runner import run_tool

# ── 全局 Agent 注册表 ─────────────────────────────────────────────────────────
_registered_agents: Dict[str, "AgentMonitor"] = {}
_agents_lock = threading.Lock()


# ── 攻击检测阈值 ───────────────────────────────────────────────────────────────
TOOL_INJECTION_THRESHOLD = 30      # 综合置信度 ≥ 30 → 阻断工具调用
SSRF_RISK_THRESHOLD = 60           # SupplyChain risk score ≥ 60 → 阻断 HTTP


class AgentMonitor:
    """
    Agent 行为监控器。
    包装外部 Agent 的工具调用，执行实时检测、策略判定、事件记录。
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str = "",
        system_prompt: str = "",
        enabled: bool = True,
    ):
        self.agent_id = agent_id
        self.agent_name = agent_name or f"Agent-{agent_id}"
        self.system_prompt = system_prompt
        self.enabled = enabled
        self.request_count = 0
        self.blocked_count = 0
        self.session_start = time.time()
        self._lock = threading.Lock()
        self._call_history: List[dict] = []

        # 加载策略引擎
        self.policy_engine = PolicyEngine()

        # 加载行为分析器
        self.behavior_analyzer = BehaviorAnalyzer()

        # 注册到全局表
        with _agents_lock:
            _registered_agents[agent_id] = self

    def execute_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        user_message: str = "",
    ) -> dict:
        """
        核心方法：执行工具调用，经过完整检测和策略判定。

        流程：
        1. 检测用户消息中的攻击意图（hybrid_detect）
        2. 通过策略引擎判定（allow / block / confirm）
        3. 记录行为事件
        4. 通过 ToolRunner 执行沙箱工具
        5. 广播 SSE 事件
        6. 返回执行结果

        参数:
            tool_name: 工具名称（read_file / send_email / http_request / query_db / post_social）
            params: 工具参数字典
            user_message: 触发本次调用的用户消息（用于攻击检测）

        返回:
            {
                "allowed": bool,       # 是否允许执行
                "tool": str,            # 工具名
                "params": dict,         # 参数（脱敏后）
                "decision": str,         # allow / block / confirm
                "reason": str,          # 判定原因
                "attack_detected": bool, # 是否检测到攻击
                "confidence": int,      # 综合置信度
                "result": dict,          # 工具执行结果（允许时）
                "call_id": str,         # 本次调用ID
            }
        """
        call_id = str(uuid.uuid4())[:8]
        timestamp = time.strftime("%H:%M:%S")

        with self._lock:
            self.request_count += 1
            req_num = self.request_count

        start = time.time()
        params_preview = self._mask_params(tool_name, params)

        # ── 步骤1：攻击意图检测 ───────────────────────────────
        attack_detected = False
        confidence = 0
        attack_reason = ""

        if user_message:
            is_mal, reason, conf_data = hybrid_detect(user_message)
            attack_detected = is_mal
            confidence = conf_data.get("combined", 0)
            attack_reason = reason

        # ── 步骤2：策略引擎判定 ──────────────────────────────
        policy_result = self.policy_engine.evaluate(tool_name, params)
        policy_action = policy_result.get("action", "allow")
        policy_reason = policy_result.get("reason", "")

        # 综合判定：策略阻断或攻击检测 → 阻断
        should_block = (
            policy_action == "block"
            or (attack_detected and confidence >= TOOL_INJECTION_THRESHOLD)
        )

        decision = "block" if should_block else "confirm" if policy_action == "confirm" else "allow"
        reason = attack_reason or policy_reason or "正常调用"

        # ── 步骤3：记录行为事件 ─────────────────────────────
        ip = "agent-internal"
        # 先计算耗时，再写事件
        elapsed_ms = int((time.time() - start) * 1000)
        event_id = add_event(
            event_type=f"Agent工具调用[{decision.upper()}]",
            detail=f"[{self.agent_name}] {tool_name}({params_preview}) | {reason[:60]}",
            status="已阻断" if decision == "block" else "待确认" if decision == "confirm" else "已放行",
            text_hash="",
            threat_level="high" if decision == "block" else "medium" if decision == "confirm" else "none",
            confidence=confidence,
            source_ip=ip,
            tool_name=tool_name,
            target=str(params)[:200],
            rule_id=f"AGENT-{decision.upper()}",
            category="Agent工具调用",
            metadata={
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "decision": decision,
                "params_preview": params_preview,
                "call_id": call_id,
                "attack_detected": attack_detected,
                "duration_ms": elapsed_ms,
            },
        )

        # 用 metadata 形式追加 agent_tool_call 类型事件（便于 /api/agent/summary 聚合）
        # 同时记录到 events 表，type='agent_tool_call' 用于精确查询
        try:
            add_event(
                event_type="agent_tool_call",
                detail=f"[{self.agent_name}] {tool_name} — {decision.upper()}",
                status="已阻断" if decision == "block" else "已放行" if decision == "allow" else "待确认",
                text_hash="",
                threat_level="high" if decision == "block" else "medium" if decision == "confirm" else "none",
                confidence=confidence,
                source_ip=ip,
                tool_name=tool_name,
                target=self.agent_id,
                rule_id=f"AGENT-{decision.upper()}",
                category="Agent工具调用",
                metadata={
                    "agent_id": self.agent_id,
                    "agent_name": self.agent_name,
                    "decision": decision,
                    "call_id": call_id,
                    "attack_detected": attack_detected,
                    "duration_ms": elapsed_ms,
                },
            )
        except Exception:
            pass

        # ── 步骤4：执行工具（仅允许时） ──────────────────────
        tool_result = {}
        if decision == "allow":
            tool_result = run_tool(
                tool_name=tool_name,
                params=json.dumps(params, ensure_ascii=False),
                source_ip=ip,
                action=tool_name,
                chain_id=None,
                token_meta={},
            )
        else:
            with self._lock:
                self.blocked_count += 1
            tool_result = {
                "status": "blocked",
                "summary": f"IShield 阻断: {reason}",
                "decision": decision,
                "confidence": confidence,
            }

        # ── 步骤5：记录调用历史 ──────────────────────────────
        call_record = {
            "call_id": call_id,
            "timestamp": timestamp,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "tool": tool_name,
            "params_preview": params_preview,
            "decision": decision,
            "reason": reason,
            "attack_detected": attack_detected,
            "confidence": confidence,
            "elapsed_ms": elapsed_ms,
            "status": "blocked" if decision == "block" else "confirmed" if decision == "confirm" else "executed",
        }
        with self._lock:
            self._call_history.append(call_record)
            # 保留最近 500 条
            if len(self._call_history) > 500:
                self._call_history = self._call_history[-500:]

        # ── 步骤6：SSE 广播 ─────────────────────────────────
        broadcast_event(
            event_type=f"Agent[{decision.upper()}]",
            detail=f"[{self.agent_name}] {tool_name} — {decision.upper()}",
            status="已阻断" if decision == "block" else "已放行",
            tool=tool_name,
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            call_id=call_id,
            confidence=confidence,
            elapsed_ms=elapsed_ms,
        )

        if decision == "block":
            broadcast_alert(
                source=f"Agent:{self.agent_name}",
                message=f"阻断恶意工具调用: {tool_name} | {reason[:40]}",
                level="high",
                confidence=confidence,
            )

        return {
            "call_id": call_id,
            "timestamp": timestamp,
            "allowed": decision != "block",
            "tool": tool_name,
            "params": params,
            "params_preview": params_preview,
            "decision": decision,
            "reason": reason,
            "attack_detected": attack_detected,
            "confidence": confidence,
            "policy_result": policy_result,
            "result": tool_result,
            "elapsed_ms": elapsed_ms,
        }

    def _mask_params(self, tool_name: str, params: Dict) -> str:
        """对敏感参数做脱敏预览"""
        masked = {}
        for k, v in params.items():
            if any(s in k.lower() for s in ["password", "key", "token", "secret", "auth"]):
                masked[k] = "***"
            elif isinstance(v, str) and len(v) > 30:
                masked[k] = v[:15] + "..."
            else:
                masked[k] = v
        return json.dumps(masked, ensure_ascii=False)[:100]

    def get_stats(self) -> dict:
        """获取该 Agent 的统计信息"""
        with self._lock:
            total = self.request_count
            blocked = self.blocked_count
            history = list(self._call_history)

        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "session_start": self.session_start,
            "total_calls": total,
            "blocked_calls": blocked,
            "block_rate": round(blocked / max(total, 1) * 100, 1),
            "uptime_seconds": int(time.time() - self.session_start),
            "recent_calls": history[-20:],
        }

    def get_recent_calls(self, limit: int = 50) -> List[dict]:
        """获取最近的调用记录"""
        with self._lock:
            return list(self._call_history[-limit:])


def get_agent_stats(agent_id: Optional[str] = None) -> dict:
    """获取 Agent 统计（单个或全部）"""
    with _agents_lock:
        if agent_id:
            agent = _registered_agents.get(agent_id)
            return agent.get_stats() if agent else {}
        return {aid: mon.get_stats() for aid, mon in _registered_agents.items()}


# ── 便捷代理工厂 ─────────────────────────────────────────────────────────────
class OpenClawProxy:
    """
    模拟 OpenClaw Agent 的工具调用接口。
    所有工具调用自动经过 AgentMonitor 监控。
    """

    def __init__(self, agent_id: str, agent_name: str = "OpenClaw"):
        self.monitor = AgentMonitor(agent_id=agent_id, agent_name=agent_name)
        self._pending_messages: List[str] = []

    def set_system_prompt(self, prompt: str):
        """设置 Agent 的系统提示词"""
        self.monitor.system_prompt = prompt

    def receive_message(self, user_message: str) -> dict:
        """
        接收用户消息（OpenClaw 入口）。
        自动分析工具调用意图并返回结果。
        """
        self._pending_messages.append(user_message)

        # 简单的工具意图检测
        is_mal, reason, conf_data = hybrid_detect(user_message)

        if is_mal and conf_data.get("combined", 0) >= TOOL_INJECTION_THRESHOLD:
            return {
                "blocked": True,
                "reason": reason,
                "confidence": conf_data.get("combined", 0),
                "message": "IShield 阻断：检测到恶意输入",
            }

        return {
            "blocked": False,
            "message": "消息已记录，等待工具调用",
            "confidence": conf_data.get("combined", 0),
        }

    def read_file(self, path: str, **kwargs) -> dict:
        """读取文件（受监控）"""
        return self.monitor.execute_tool("read_file", {"path": path, **kwargs})

    def write_file(self, path: str, content: str, **kwargs) -> dict:
        """写入文件（受监控）"""
        return self.monitor.execute_tool("write_file", {"path": path, "content": content, **kwargs})

    def send_email(self, to: str, subject: str, body: str, **kwargs) -> dict:
        """发送邮件（受监控）"""
        return self.monitor.execute_tool(
            "send_email", {"to": to, "subject": subject, "body": body, **kwargs}
        )

    def http_request(self, url: str, method: str = "GET", **kwargs) -> dict:
        """发送 HTTP 请求（受监控）"""
        return self.monitor.execute_tool(
            "http_request", {"url": url, "method": method, **kwargs}
        )

    def query_db(self, query: str, **kwargs) -> dict:
        """查询数据库（受监控）"""
        return self.monitor.execute_tool("query_db", {"query": query, **kwargs})

    def post_social(self, platform: str, content: str, **kwargs) -> dict:
        """发布社交媒体（受监控）"""
        return self.monitor.execute_tool(
            "post_social", {"platform": platform, "content": content, **kwargs}
        )

    def get_stats(self) -> dict:
        return self.monitor.get_stats()

    def get_call_history(self, limit: int = 50) -> List[dict]:
        return self.monitor.get_recent_calls(limit)


def create_openclaw_proxy(agent_id: str = "openclaw-default", agent_name: str = "OpenClaw Demo") -> OpenClawProxy:
    """创建受监控的 OpenClaw 代理实例"""
    return OpenClawProxy(agent_id=agent_id, agent_name=agent_name)
