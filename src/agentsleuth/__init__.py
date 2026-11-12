"""AgentSleuth — deterministic, LLM-free forensic reconstruction for AI agents.

Reconstruct which untrusted input caused which dangerous action after a
prompt-injection attack, with no LLM in the loop.

    from agentsleuth import TaintTracer
    from agentsleuth.adapters import get_adapter

    run = get_adapter("agentdojo")(run_json)
    findings = TaintTracer(rules="v4").trace(run)
    print(findings.alerted(), [str(a) for a in findings.alerts])
"""
from .core import (
    Run, Step, ToolCall,
    TaintTracer, Findings, Alert, DEFAULT_SINKS,
    to_text, to_json,
)
from .adapters import get_adapter, available, register_adapter

__version__ = "0.1.0"
__all__ = [
    "Run", "Step", "ToolCall",
    "TaintTracer", "Findings", "Alert", "DEFAULT_SINKS",
    "to_text", "to_json",
    "get_adapter", "available", "register_adapter",
    "__version__",
]
