# mcp-assess

Authorized MCP Assessment CLI for researchers. Discovers Host Configs (Cursor, Claude Desktop, VS Code), maps Target surfaces, runs Checks grounded in OWASP MCP Top 10 (with MITRE ATLAS secondary citations), and writes a markdown + JSON Report.

This is not an exploit kit. Honor-system authorization: if you name the Target, that is enough.

## Install

```bash
uvx mcp-assess --help
# or
pip install -e .
mcp-assess --help
```

## Quick start

```bash
# Assess Cursor Host Config Targets (default discovery)
mcp-assess --out ./reports/run1

# All known Hosts on this machine
mcp-assess --all-hosts --out ./reports/run1

# Explicit remote Target
mcp-assess --url https://mcp.example/mcp --bearer "$TOKEN" --out ./reports/run1

# With Judge (required for poisoning-class Checks)
export MCP_ASSESS_JUDGE_CMD='llm -m gpt-4.1-mini'
mcp-assess --config ~/.cursor/mcp.json --judge-cmd "$MCP_ASSESS_JUDGE_CMD"
```

## Modes

| Mode | Behavior |
| --- | --- |
| **Safe** (default) | Config + Enumerate + AuthZ probes + low-impact Invoke |
| **`--unsafe`** | + mutate-looking non-high-impact Invoke; alternate-path probes |
| **`--probe-high-impact`** | Required before any high-impact Invoke |

## Spec

Product decisions and Check catalog: [`docs/spec.md`](docs/spec.md), vocabulary in [`CONTEXT.md`](CONTEXT.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Completed; no high/critical Findings |
| 1 | Completed; one or more high/critical Findings |
| 2 | Aborted (invalid flags, connect failure with nothing Assessed, Judge fail-fast) |
