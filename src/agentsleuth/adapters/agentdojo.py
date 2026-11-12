"""Adapter for AgentDojo run logs (https://github.com/ethz-spylab/agentdojo).

An AgentDojo run is a JSON object with a "messages" list. Each message has a
role, a structured "content" field, and, for assistant steps, "tool_calls" with
a function name and an args dict. The account owner's mailbox address is a
deployment constant, exposed here so the tracer can trust it as configuration.
"""
from __future__ import annotations

from ..core.schema import Run, Step, ToolCall
from .base import register_adapter

# The AgentDojo workspace suite runs as this simulated employee.
WORKSPACE_OWNER = frozenset({"emma.johnson@bluesparrowtech.com"})


def _text_of(message: dict) -> str:
    content = message.get("content") or []
    if isinstance(content, str):
        return content
    return " ".join(c.get("content", "") for c in content if isinstance(c, dict))


def to_run(raw: dict) -> Run:
    """Convert one AgentDojo run dict (with a 'messages' list) into a Run."""
    steps = []
    for i, m in enumerate(raw.get("messages", [])):
        calls = [
            ToolCall(function=t.get("function", ""), args=t.get("args") or {})
            for t in (m.get("tool_calls") or [])
        ]
        steps.append(Step(index=i, role=m.get("role", ""),
                          text=_text_of(m), tool_calls=calls))
    return Run(steps=steps)


register_adapter("agentdojo", to_run)
