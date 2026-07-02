"""Behavior risk scoring engine — explainable runtime risk factors."""
import threading
import time
from collections import Counter, defaultdict, deque
from typing import Any, Dict, List


class RiskEngine:
    def __init__(self):
        self._lock = threading.RLock()
        self._ip_scores = defaultdict(int)
        self._token_scores = defaultdict(int)
        self._session_scores = defaultdict(int)
        self._history = deque(maxlen=1200)
        self._runtime_history = deque(maxlen=800)
        self._factor_counter = Counter()

    def record(self, ip: str = None, token: str = None, session: str = None,
               score: int = 0, reason: str = "", source: str = "") -> dict:
        with self._lock:
            now = time.time()
            if ip:
                self._ip_scores[ip] += score
            if token:
                self._token_scores[token] += score
            if session:
                self._session_scores[session] += score
            action = self._decide_action(ip, token, session)
            entry = {
                "ts": now,
                "ip": ip,
                "token": token,
                "session": session,
                "score": score,
                "reason": reason,
                "source": source,
                "action": action,
            }
            self._history.append(entry)
            return {
                "ip_score": self._ip_scores.get(ip, 0) if ip else 0,
                "token_score": self._token_scores.get(token, 0) if token else 0,
                "session_score": self._session_scores.get(session, 0) if session else 0,
                "action": action,
            }

    def score_runtime(self, action: str, target: str = "", decision: str = "allowed",
                      blocked_at: str = "none", input_score: int = 0,
                      policy_trace: dict = None, tool_result: dict = None,
                      source_ip: str = None, token: str = None, session: str = None,
                      chain_id: str = None, actor: str = None) -> dict:
        """Score one runtime action with factor-level explanation."""
        policy_trace = policy_trace or {}
        tool_result = tool_result or {}
        audit = tool_result.get("audit") or {}
        factors: List[Dict[str, Any]] = []

        _add_factor(factors, "input_intent", input_score, "输入检测风险分")

        policy_severity = int(policy_trace.get("severity") or 0)
        if policy_trace.get("triggered_rule"):
            _add_factor(
                factors,
                "policy_hit",
                policy_severity,
                f"命中策略 {policy_trace.get('triggered_rule')}，动作={policy_trace.get('action')}",
                evidence={
                    "rule_id": policy_trace.get("triggered_rule"),
                    "scope": policy_trace.get("scope"),
                    "priority": policy_trace.get("priority"),
                },
            )

        tool_severity = int(audit.get("severity") or _tool_status_score(tool_result.get("status")))
        if tool_result:
            _add_factor(
                factors,
                "tool_execution",
                tool_severity,
                tool_result.get("summary") or "工具沙箱返回运行结果",
                evidence={"status": tool_result.get("status"), "rule_id": audit.get("rule_id")},
            )

        target_score, target_reason = _target_sensitivity(action, target)
        _add_factor(factors, "target_sensitivity", target_score, target_reason)

        decision_score = {
            "blocked": 18,
            "confirm": 12,
            "timeout": 15,
            "error": 12,
            "allowed": 0,
        }.get(str(decision or "").lower(), 4)
        _add_factor(factors, "runtime_decision", decision_score, f"运行时最终处置={decision}")

        history_score = self._history_score(source_ip, token, session)
        _add_factor(factors, "behavior_history", history_score, "同源 IP/Token/Session 历史风险累积")

        total = min(100, max(0, sum(int(f.get("score") or 0) for f in factors)))
        level = _score_to_level(total)
        disposition = _action_for_score(total, decision)
        contribution = max(0, min(35, total // 3))
        accumulator = self.record(
            ip=source_ip,
            token=token,
            session=session,
            score=contribution,
            reason=f"runtime:{action}:{decision}:{blocked_at}",
            source="runtime_gateway",
        )

        result = {
            "risk_score": total,
            "risk_level": level,
            "risk_factors": [f for f in factors if int(f.get("score") or 0) > 0],
            "all_factors": factors,
            "disposition": disposition,
            "recommendation": _recommendation_for_score(total, disposition, blocked_at),
            "accumulator": accumulator,
            "chain_id": chain_id,
            "source_ip": source_ip,
            "actor": actor,
            "action": action,
            "target": target,
            "decision": decision,
            "blocked_at": blocked_at,
        }
        with self._lock:
            self._runtime_history.append({**result, "ts": time.time()})
            for factor in result["risk_factors"]:
                self._factor_counter[factor["factor"]] += 1
        return result

    def _history_score(self, ip: str = None, token: str = None, session: str = None) -> int:
        max_score = max(
            self._ip_scores.get(ip, 0) if ip else 0,
            self._token_scores.get(token, 0) if token else 0,
            self._session_scores.get(session, 0) if session else 0,
        )
        if max_score >= 120:
            return 18
        if max_score >= 70:
            return 12
        if max_score >= 35:
            return 7
        return 0

    def _decide_action(self, ip: str, token: str, session: str) -> str:
        max_score = max(
            self._ip_scores.get(ip, 0) if ip else 0,
            self._token_scores.get(token, 0) if token else 0,
            self._session_scores.get(session, 0) if session else 0,
        )
        if max_score >= 120:
            return "block"
        if max_score >= 70:
            return "readonly"
        if max_score >= 35:
            return "challenge"
        return "allow"

    def score_cluster(self, cluster_id: str, session_id: str = None, scenario: str = "",
                      agent_path: list = None, violations: list = None,
                      runtime_results: list = None, source_ip: str = None) -> dict:
        """Score a multi-agent session with cluster-level risk factors."""
        agent_path = agent_path or []
        violations = violations or []
        runtime_results = runtime_results or []
        factors: List[Dict[str, Any]] = []

        violation_scores = {
            "agent_role_mismatch": 26,
            "delegation_violation": 30,
            "privilege_escalation": 34,
            "cross_agent_contamination": 28,
            "tool_chain_amplification": 24,
            "session_risk_accumulation": 16,
        }
        for item in violations:
            vtype = item.get("type") or "agent_role_mismatch"
            _add_factor(
                factors,
                vtype,
                item.get("score") or violation_scores.get(vtype, 18),
                item.get("reason") or vtype,
                evidence={
                    "agent_id": item.get("agent_id"),
                    "agent_role": item.get("agent_role"),
                    "action": item.get("action"),
                    "target": item.get("target"),
                },
            )

        max_runtime = max((int((item.get("risk_assessment") or {}).get("risk_score") or item.get("risk_score") or 0) for item in runtime_results), default=0)
        if max_runtime:
            _add_factor(
                factors,
                "runtime_gateway_risk",
                min(35, max_runtime // 2),
                "下游运行时网关返回了高风险工具调用结果",
                evidence={"max_runtime_risk": max_runtime},
            )

        if len(agent_path) >= 4:
            _add_factor(
                factors,
                "tool_chain_amplification",
                18 + min(12, len(agent_path) * 2),
                "多段 Agent / 工具跳转扩大了风险影响面",
                evidence={"agent_path": agent_path},
            )

        history_score = self._history_score(source_ip, None, session_id)
        _add_factor(factors, "session_risk_accumulation", history_score, "同一会话或来源已累积历史风险")

        total = min(100, max(0, sum(int(f.get("score") or 0) for f in factors)))
        if any((item.get("decision") == "blocked" or item.get("result") == "blocked") for item in runtime_results):
            total = max(total, 72)
        if any(item.get("type") in {"privilege_escalation", "delegation_violation"} for item in violations):
            total = max(total, 88)

        level = _score_to_level(total)
        disposition = _action_for_score(total, "blocked" if total >= 85 else "confirm" if total >= 65 else "allowed")
        accumulator = self.record(
            ip=source_ip,
            session=session_id,
            score=max(8, min(35, total // 3)) if total else 0,
            reason=f"agent_cluster:{scenario}:{disposition}",
            source="agent_cluster",
        )
        result = {
            "risk_score": total,
            "risk_level": level,
            "risk_factors": [f for f in factors if int(f.get("score") or 0) > 0],
            "all_factors": factors,
            "disposition": disposition,
            "recommendation": _cluster_recommendation(total, disposition),
            "accumulator": accumulator,
            "cluster_id": cluster_id,
            "session_id": session_id,
            "scenario": scenario,
            "agent_path": agent_path,
            "source_ip": source_ip,
            "action": "agent_cluster",
            "decision": "blocked" if disposition == "block" else "confirm" if disposition == "challenge" else "allowed",
            "blocked_at": "agent_cluster" if disposition in {"block", "challenge"} else "none",
        }
        with self._lock:
            self._runtime_history.append({**result, "ts": time.time()})
            for factor in result["risk_factors"]:
                self._factor_counter[factor["factor"]] += 1
        return result

    def get_summary(self) -> dict:
        with self._lock:
            top_ips = sorted(self._ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
            top_tokens = sorted(self._token_scores.items(), key=lambda x: x[1], reverse=True)[:10]
            runtime = list(self._runtime_history)
            recent = runtime[-50:]
            current_risk = max((int(item.get("risk_score") or 0) for item in recent), default=0)
            high_count = sum(1 for item in recent if int(item.get("risk_score") or 0) >= 70)
            blocked_count = sum(1 for item in recent if item.get("decision") == "blocked")
            avg_score = round(sum(int(item.get("risk_score") or 0) for item in recent) / len(recent), 2) if recent else 0
            stage_counter = Counter(item.get("blocked_at") or "none" for item in recent)
            action_counter = Counter(item.get("action") or "unknown" for item in recent)
            top_factors = [
                {"factor": key, "count": value}
                for key, value in self._factor_counter.most_common(8)
            ]
            return {
                "current_risk_index": current_risk,
                "current_risk_level": _score_to_level(current_risk),
                "avg_runtime_risk": avg_score,
                "high_risk_runtime_count": high_count,
                "blocked_runtime_count": blocked_count,
                "total_runtime_records": len(runtime),
                "blocked_at_distribution": dict(stage_counter),
                "action_distribution": dict(action_counter),
                "top_risk_factors": top_factors,
                "top_risky_ips": [{"ip": k, "score": v} for k, v in top_ips],
                "top_risky_tokens": [{"token": k, "score": v} for k, v in top_tokens],
                "recent_actions": list(self._history)[-20:],
                "recent_runtime": recent[-10:],
            }


def _add_factor(factors: list, factor: str, score: int, reason: str, evidence: dict = None):
    score = int(score or 0)
    factors.append({
        "factor": factor,
        "score": max(0, min(100, score)),
        "reason": reason,
        "evidence": evidence or {},
    })


def _tool_status_score(status: str) -> int:
    return {
        "blocked": 35,
        "pending": 25,
        "timeout": 30,
        "error": 25,
        "executed": 8,
        "mock": 6,
    }.get(str(status or "").lower(), 12)


def _target_sensitivity(action: str, target: str) -> tuple[int, str]:
    text = f"{action or ''} {target or ''}".lower()
    if any(term in text for term in [".env", "id_rsa", "passwd", "shadow", "secret", "token", "api_key"]):
        return 22, "目标包含敏感路径、凭证或密钥语义"
    if any(term in text for term in ["outside", "external", "evil", "phish", "http://", "https://"]):
        return 18, "目标包含外联或外发风险语义"
    if any(term in text for term in ["admin", "root", "password"]):
        return 15, "目标涉及管理员或敏感字段"
    return 0, "目标未显示额外敏感性"


def _score_to_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _action_for_score(score: int, decision: str) -> str:
    if str(decision or "").lower() == "blocked" or score >= 85:
        return "block"
    if score >= 65:
        return "challenge"
    if score >= 35:
        return "monitor"
    return "allow"


def _recommendation_for_score(score: int, disposition: str, blocked_at: str) -> str:
    if disposition == "block":
        return f"保持 {blocked_at or 'runtime'} 阶段阻断，并将该行为加入联动验证回归集。"
    if disposition == "challenge":
        return "要求确认业务目的，降权执行工具并保留审批与执行后审计。"
    if disposition == "monitor":
        return "允许低风险链路继续运行，但提高同源调用的观察频率。"
    return "允许执行并保留完整审计证据。"


def _cluster_recommendation(score: int, disposition: str) -> str:
    if disposition == "block":
        return "阻断委托动作，冻结当前集群会话，并复核引入高风险指令的上游 Agent。"
    if disposition == "challenge":
        return "继续执行 Agent 链路前需要确认，并临时降低本会话的下游工具权限。"
    if score >= 35:
        return "可在增强监控下放行，并保留完整 Agent 路径用于后续审计。"
    return "允许集群继续运行，并保留 Agent 路径、角色校验和运行时证据。"


_ENGINE = None
_ENGINE_LOCK = threading.Lock()


def get_risk_engine() -> RiskEngine:
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None:
            _ENGINE = RiskEngine()
        return _ENGINE
