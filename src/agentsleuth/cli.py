"""Command-line interface.

    agentsleuth trace RUN.json --adapter agentdojo --rules v4 --format text

Exit code is 1 when any alert is raised, so AgentSleuth can gate a triage or CI
pipeline.
"""
from __future__ import annotations

import argparse
import json
import sys

from .adapters import get_adapter
from .adapters.agentdojo import WORKSPACE_OWNER
from .core import TaintTracer, to_json, to_text

# account-owner identifiers trusted by deployment config, per adapter
DEFAULT_OWNER = {"agentdojo": WORKSPACE_OWNER}


def _trace_cmd(args: argparse.Namespace) -> int:
    with open(args.path, encoding="utf-8") as fh:
        raw = json.load(fh)
    run = get_adapter(args.adapter)(raw)
    owner = set(args.owner) if args.owner else set(DEFAULT_OWNER.get(args.adapter, set()))
    findings = TaintTracer(rules=args.rules, owner=owner).trace(run)
    out = to_json(findings, args.path) if args.format == "json" else to_text(findings, args.path)
    print(out)
    return 1 if findings.alerted() else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentsleuth",
                                     description="Deterministic forensic reconstruction for AI agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    t = sub.add_parser("trace", help="trace one agent-run log")
    t.add_argument("path", help="path to a run log (JSON)")
    t.add_argument("--adapter", default="agentdojo", help="log format adapter (default: agentdojo)")
    t.add_argument("--rules", default="v4", choices=["v2", "v3", "v4"],
                   help="detector rule set (default: v4)")
    t.add_argument("--format", default="text", choices=["text", "json"],
                   help="output format (default: text)")
    t.add_argument("--owner", nargs="*", default=None,
                   help="account-owner identifiers trusted as config (overrides adapter default)")
    t.set_defaults(func=_trace_cmd)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
