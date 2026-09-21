# mcp-assess — Product specification (v1)

**Status:** Ready for implementation  
**Vocabulary:** [`CONTEXT.md`](../CONTEXT.md)  
**Decision trail:** [`.scratch/mcp-assess/map.md`](../.scratch/mcp-assess/map.md)

This document is the implementer handoff. Do not re-litigate product decisions here — change them via the wayfinder map.

---

## 1. Destination

A Python CLI **`mcp-assess`**, installable via `uvx` / pip, that runs an authorized **Assessment** of MCP **Targets** (from Host Configs and/or explicit URLs), builds **Surface Maps**, runs **Checks** grounded in OWASP MCP Top 10 (deep on MCP03 / MCP07) with MITRE ATLAS secondary citations, and writes a **Report** as **JSON + markdown** with the same content.

It is not an exploit kit. Honor-system authorization: if the operator named the Target, that is enough.

---

## 2. Non-goals (v1)

- Interactive OAuth / device-code flows (pass-through Host Config env/headers and `--bearer` / `--header` only)
- CI-first product (exit codes exist; laptop is primary)
- Mandatory OS/container sandbox for STDIO spawn (spawn as-is; Report notes no sandbox)
- Third-party hosted poisoning API as default Judge
- Heuristics-only poisoning verdicts (Judge required for poisoning-class Checks)
- SARIF output

---

## 3. Runtime & transports

- Language: **Python 3**
- Pin MCP SDK: **`mcp` 2.2.0** (see [`research/python-mcp-transports.md`](../research/python-mcp-transports.md))
- Transports (all first-class): **STDIO**, **SSE** (legacy `sse_client`), **Streamable HTTP**
- High-level `Client`; cursor-loop all list methods for full Surface Maps
- STDIO: merge Host Config `env` over SDK allow-list; spawn **on by default** for Host Config Targets (`--no-spawn` to disable)
- Streamable HTTP auth: BYO `httpx` client with headers (no `headers=` on helper alone)
- Spec gaps to honor: SSE vs Streamable auth API divergence; `is_error` vs exceptions; no interactive OAuth

---

## 4. Host Config discovery

See [`research/host-config-discovery.md`](../research/host-config-discovery.md).

| Host | Paths (summary) | Root key |
| --- | --- | --- |
| Cursor | `~/.cursor/mcp.json`, project `.cursor/mcp.json` (merge; project wins) | `mcpServers` |
| Claude Desktop | OS app-support `claude_desktop_config.json` (macOS/Windows; Linux via XDG secondary) | `mcpServers` |
| VS Code | user `mcp.json`, `.vscode/mcp.json` | `servers` |

**Target id:** normalized `command`+`args` or normalized URL, plus Host Config path when discovered locally.

**Claude Desktop remotes:** Connectors UI remotes are not in the STDIO config file — Assessment should note undiscoverable remotes in the Report when Claude Desktop Host is selected; do not invent Connector scraping in v1.

---

## 5. CLI surface

Full flag table: [Grill CLI surface for mcp-assess](../.scratch/mcp-assess/issues/11-grill-cli-surface.md).

Summary:

```text
mcp-assess [options]           # default: run Assessment
mcp-assess pin list|show|delete
```

Key flags: `--config`, `--all-hosts`, `--target`, `--url`, `--header`, `--bearer`, `--alt-target`, `--unsafe`, `--probe-high-impact`, `--high-impact-extra`, `--high-impact-except`, `--no-spawn`, `--judge-cmd`, `--judge-timeout`, `--judge-fail-fast`, `--judge-verbose`, `--pin-store`, `--approve`, `--approve-target`, `--out`, `--show-secrets`.

Env: `MCP_ASSESS_JUDGE_CMD` (overridden by `--judge-cmd`).

Exit: `0` ok / no high+ Findings; `1` high|critical Findings; `2` aborted.

---

## 6. Assessment Mode & Invoke policy

Full text: [Grill Invoke policy Safe Unsafe high-impact](../.scratch/mcp-assess/issues/08-grill-invoke-policy.md).  
AuthZ patterns: [`research/mcp-broken-authz-checks.md`](../research/mcp-broken-authz-checks.md).

| Mode | Behavior |
| --- | --- |
| **Safe** (default) | Config + Enumerate + AuthZ probes + low-impact Invoke |
| **Unsafe** | + mutate-looking non-high-impact Invoke; alternate-path probes |
| **`--probe-high-impact`** | Required for high-impact Invoke |

Classifier **`high-impact-v1`:** verb/token families (exec/shell/delete/write/egress/admin/…). Overrides via flags. Minimal inert args only. No session hijack; no blind tool-name guessing.

Record `assessment.invoke_policy` in the Report.

---

## 7. Judge contract

Full text: [Grill Judge shell-out contract](../.scratch/mcp-assess/issues/06-grill-judge-shell-out-contract.md).

- Template placeholders: `{prompt_file}`, `{timeout_ms}`, `{check_id}`, `{subject_kind}`
- Request JSON on stdin (`schema_version`, `check_id`, `target_id`, `subject_kind`, `subject`, `rubric`)
- Response: last JSON object — `verdict` ∈ clean|suspicious|poisoned|error, `score`, `rationale`, optional `severity_hint`
- Missing Judge / failure → never `clean`
- Default timeout 60s; sequential calls
- Ship packaged example templates for `llm` and Cursor Agent under package `share/` (or equivalent) + appendix below

### Example templates (illustrative)

**llm (stdin JSON → stdout JSON):** operator wraps a schema-constrained prompt that prints only the verdict object.

**Cursor Agent:** use `{prompt_file}` with `agent -p "$(cat {prompt_file})"` (or current CLI equivalent); parse last JSON from output.

---

## 8. Pin store

Full text: [Grill Pin store and approve workflow](../.scratch/mcp-assess/issues/10-grill-pin-store-and-approve.md).

- Default: `~/.mcp-assess/pins/` (`index.json` + per-key files)
- Hash canonical JSON of tool/prompt/resource **metadata** (not bodies; not full text in store)
- `--approve` baselines; drift → `PIN-DEFINITION-DRIFT`; first run informational only

---

## 9. Report schema

Full text: [Grill Report schema](../.scratch/mcp-assess/issues/07-grill-report-schema.md).

```text
schema_version: 1
assessment, hosts[], targets[], surface_maps[], findings[], manual_checks[]
```

Finding: catalog envelope + `id`, `title`, `redacted`, optional `remediation: { summary, urls[] }`.  
Markdown mirrors JSON via fixed headings; Cross-server section filters Findings.  
Secrets redacted by default.

---

## 10. Surface Map

Shape + fixture: [Prototype Surface Map outline](../.scratch/mcp-assess/issues/09-prototype-surface-map-outline.md),  
[`prototypes/surface-map-outline.md`](../.scratch/mcp-assess/prototypes/surface-map-outline.md).

Per-Target maps: config wiring, initialize caps, tools by `capability_class` / `impact_class`, resources/prompts, allowlist hints, `weakness_hypotheses`.  
Optional Host-scoped map for `cross_server` toxic-flow / name-collision hypotheses. Hypotheses ≠ Findings.

---

## 11. Check catalog

Normative catalog: [`research/owasp-mcp-check-catalog.md`](../research/owasp-mcp-check-catalog.md) (31 Checks).

| Depth | OWASP |
| --- | --- |
| Deep | MCP03, MCP07 |
| Light + manuals | MCP01, 02, 04, 05, 06, 08, 09, 10 |

ATLAS secondaries: [`research/atlas-citation-map.md`](../research/atlas-citation-map.md) — OWASP primary; agent-tool techniques when fit; MCP07/MCP08 often no clean fit.

Implement Checks as named modules keyed by catalog `check_id`. Rubrics for `JUDGE-*` Checks are spec-owned strings passed in the Judge request.

---

## 12. Packaging

- Distribution name / console script: **`mcp-assess`**
- Support `pip install` and `uvx mcp-assess`
- Include Judge template files in the package
- Exact PyPI ownership / versioning scheme: implementer choice; start at `0.1.0`

---

## 13. Implementation order (suggested)

1. Host Config discovery + Target id normalization  
2. Transport client (STDIO / HTTP / SSE) + Enumerate → Surface Map  
3. Report writer (JSON + markdown)  
4. Config/Enumerate Checks (secrets, allowlists, shadowing, pins)  
5. Judge integration + JUDGE-* Checks  
6. Invoke AuthZ Checks under Mode policy  
7. CLI polish + templates + `uvx` entry point  

---

## 14. Open items (not blocking v1 build)

- Lab / fixture Targets for demos  
- Finer Claude Desktop Connector discovery (beyond Report note)  
- Judge call parallelism  

---

## Appendix A — Decision index

See map [Decisions so far](../.scratch/mcp-assess/map.md#decisions-so-far). All research under [`research/`](../research/).
