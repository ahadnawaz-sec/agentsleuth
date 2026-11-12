# AgentSleuth

**Deterministic, LLM-free forensic reconstruction for AI agents.**

When an AI agent is hijacked by a prompt-injection attack, an investigator needs to know
*which untrusted input caused which dangerous action*. AgentSleuth reconstructs that chain
from an agent's run log using string provenance (taint tracking) — **with no LLM in the
loop**, so the investigator itself cannot be prompt-injected.

- **Deterministic & auditable** — every alert cites a concrete flow of untrusted
  (tool-sourced) data into a sensitive tool call. No model calls, no network, no randomness.
- **Framework-agnostic** — one core engine over a normalized run schema; add a new framework
  with a small adapter.
- **Zero dependencies** — the core uses only the Python standard library.

## Install

```bash
pip install agentsleuth
```

## Quickstart (library)

```python
import json
from agentsleuth import TaintTracer
from agentsleuth.adapters import get_adapter

raw = json.load(open("run.json"))
run = get_adapter("agentdojo")(raw)

findings = TaintTracer(rules="v4").trace(run)
if findings.alerted():
    for a in findings.alerts:
        print(a)   # e.g. [step 4] send_email: target from a source the user never named ...
```

## Quickstart (CLI)

```bash
agentsleuth trace run.json --adapter agentdojo --rules v4
# exit code 1 if any alert is raised (usable in triage / CI)
```

## Detector rule sets

| rules | what it adds |
|-------|--------------|
| `v2`  | taint only — any untrusted atom reaching a sink |
| `v3`  | + authorisation (the action must be user-requested or delegated) and target provenance |
| `v4`  | + provenance **locality** (same-record clearance) and destructive short-id checks (default) |

`v4` is the recommended default: it keeps high recall while flagging only genuine
untrusted-to-sink flows.

## Adapters

An adapter converts one framework's raw log into the normalized `Run` schema. Ships with an
AgentDojo adapter; add your own framework in a single file:

```python
from agentsleuth import Run, Step, ToolCall
from agentsleuth.adapters import register_adapter

def to_run(raw) -> Run:
    ...  # map your log to Steps
register_adapter("myframework", to_run)
```

## Reproducing the research results

`examples/reproduce_paper.py` runs the tracer over AgentDojo logs and prints the
precision/recall tables for v2/v3/v4:

```bash
python examples/reproduce_paper.py /path/to/<model>/workspace
```

## Paper

AgentSleuth implements the detector from *Forensic Readiness of AI Agents: Reconstructing
Prompt-Injection Attacks Without Trusting the LLM* (Ahad Nawaz). The full write-up and
citation will be linked here on release.

## License

MIT — see [LICENSE](LICENSE).
