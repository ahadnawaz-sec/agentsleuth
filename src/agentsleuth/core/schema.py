"""Normalized agent-run schema.

Every adapter converts a framework's raw log into a `Run`: an ordered list of
`Step`s. The tracer never sees framework-specific formats -- only this schema.

Trust model (the whole basis of the analysis):
  - system + user text is TRUSTED (it is what the operator and user wrote).
  - tool outputs are UNTRUSTED (an attacker can plant text in them).
  - tool calls are where the agent acts; a configurable subset are SINKS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """A single tool/function invocation the agent made."""
    function: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class Step:
    """One message in the run, at its original position (`index`)."""
    index: int
    role: str                       # "system" | "user" | "assistant" | "tool"
    text: str = ""                  # message text (tool output, or assistant content)
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass
class Run:
    """A full agent run: the ordered steps of one task execution."""
    steps: list[Step] = field(default_factory=list)

    # --- trusted text -------------------------------------------------------
    def system_text(self) -> str:
        return " ".join(s.text for s in self.steps if s.role == "system")

    def user_text(self) -> str:
        return " ".join(s.text for s in self.steps if s.role == "user")

    def trusted_text(self) -> str:
        """System + user text, lower-cased: what the attacker does NOT control."""
        return (self.system_text() + " " + self.user_text()).lower()

    # --- untrusted sources --------------------------------------------------
    def tool_outputs(self) -> list[tuple[int, str]]:
        """(step_index, lower-cased text) for every tool output (untrusted)."""
        return [(s.index, s.text.lower()) for s in self.steps if s.role == "tool"]

    def tool_text_by_index(self) -> dict[int, str]:
        """step_index -> raw tool-output text (for provenance locality checks)."""
        return {s.index: s.text for s in self.steps if s.role == "tool"}

    # --- actions ------------------------------------------------------------
    def calls(self) -> list[tuple[int, ToolCall]]:
        """(step_index, ToolCall) for every tool call the agent made, in order."""
        return [(s.index, tc) for s in self.steps for tc in s.tool_calls]

    def first_user_text(self) -> str:
        for s in self.steps:
            if s.role == "user":
                return s.text
        return ""
