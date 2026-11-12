"""Render findings as a human-readable or machine-readable report."""
from __future__ import annotations

import json

from .tracer import Findings


def to_text(findings: Findings, run_name: str = "") -> str:
    head = f"AgentSleuth report{(' — ' + run_name) if run_name else ''}"
    if not findings.alerted():
        return f"{head}\n  no untrusted-to-sink flow detected."
    lines = [head, f"  {len(findings.alerts)} alert(s):"]
    for a in findings.alerts:
        lines.append(f"  - {a}")
    return "\n".join(lines)


def to_json(findings: Findings, run_name: str = "") -> str:
    return json.dumps({
        "run": run_name,
        "alerted": findings.alerted(),
        "alerts": [
            {"step": a.step, "tool": a.tool, "reason": a.reason,
             "tainted": a.tainted, "sources": a.sources}
            for a in findings.alerts
        ],
    }, indent=2)
