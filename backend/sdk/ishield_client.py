"""Minimal IShield v5.8 Agent Runtime Protocol client."""
from __future__ import annotations

import json
import urllib.request
import uuid
from typing import Any, Dict


class IShieldClient:
    """Small dependency-free client for embedding IShield in Agent apps."""

    def __init__(self, base_url: str = "http://127.0.0.1:5000", agent_id: str = None, session_id: str = None):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id or "external-agent"
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:10]}"
        self.chain_id = f"chain-{self.session_id}"

    def guard_tool_call(self, tool_name: str, tool_args: Dict[str, Any], input_text: str = "") -> Dict[str, Any]:
        """Ask IShield whether a tool call should run."""
        return self._post("/api/runtime/decision", {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "chain_id": self.chain_id,
            "step_type": "tool_call",
            "tool_name": tool_name,
            "tool_args": tool_args,
            "input": input_text,
        })

    def report_agent_step(self, step_type: str, **fields: Any) -> Dict[str, Any]:
        """Report an Agent planning, memory, RAG, delegation or output step."""
        payload = {
            "agent_id": fields.pop("agent_id", self.agent_id),
            "session_id": fields.pop("session_id", self.session_id),
            "chain_id": fields.pop("chain_id", self.chain_id),
            "step_type": step_type,
            **fields,
        }
        return self._post("/api/runtime/ingest", payload)

    def audit_memory(self, content: str, scope: str = "session", operation: str = "write") -> Dict[str, Any]:
        step_type = "memory_write" if operation != "read" else "memory_read"
        return self.report_agent_step(step_type, memory={"content": content, "scope": scope, "operation": operation})

    def audit_rag(self, query: str, corpus: str = "default") -> Dict[str, Any]:
        return self.report_agent_step("rag_query", rag={"query": query, "corpus": corpus})

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        if not data.get("success", False):
            raise RuntimeError(data.get("message") or data.get("error") or "IShield request failed")
        return data.get("data") or data
