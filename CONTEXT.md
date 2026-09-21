# MCP assessment

Language for an authorized MCP Assessment tool — a researcher-facing scanner that maps Targets the operator is allowed to test, and produces a Report grounded in MITRE ATLAS, OWASP MCP Top 10, and published MCP weakness research (especially broken authorization).

## Language

**Assessment**:
A run of the tool against one or more Targets the operator is allowed to test. An Assessment covers Host Config understanding, live Surface mapping, and Checks. It is not an exploit kit.
_Avoid_: recon, pentest, attack, exploit

**Target**:
An MCP server under Assessment. A Target is either discovered from a Host Config or supplied explicitly by the operator.
_Avoid_: endpoint, instance, server (when you mean the thing under test — say Target)

**Host**:
The agent application on the operator’s machine whose MCP setup is being mapped (Cursor, Claude Desktop, VS Code, and similar).
_Avoid_: client, IDE, runner (when you mean the app that owns the config)

**Host Config**:
The file (or files) in which a Host declares which MCP servers it launches or connects to, including command, URL, and environment values.
_Avoid_: mcp.json (the filename of one Host Config, not the concept)

**Surface Map**:
The researcher-facing picture of a Target (and optional Host-scoped cross-server view): config wiring, Transport, initialize capabilities, tools/resources/prompts grouped by capability and impact class, allowlist hints, and weakness hypotheses that point at Check ids. Understanding only — not a Finding. Shape locked by the Surface Map prototype fixture.
_Avoid_: inventory dump, recon map, attack surface (when you mean the structured understanding artifact)

**Check**:
A named test in an Assessment that looks for a specific weakness class (for example: secrets in Host Config, list-vs-call authorization gap, missing server authentication). A Check may be config-only, enumerate-only, or may Invoke a tool under operator authorization.
_Avoid_: rule, detector, exploit

**Invoke**:
Calling a Target’s tool via MCP `tools/call` (or an equivalent path) during an Assessment, under operator authorization. Not the same as Enumerate (`tools/list` and related list methods). Breadth of Invoke is gated by Assessment Mode.
_Avoid_: exploit, weaponize, PoC against third parties

**Assessment Mode**:
A run-wide switch that bounds how aggressive Checks and Invokes may be. **Safe** (default) = Enumerate + AuthZ probes + Invoke of low-impact tools/resources/prompts + all static Checks. **Unsafe** (`--unsafe`) = Safe plus mutate-looking non-high-impact Invoke and operator-declared alternate-path probes. High-impact Invokes require `--probe-high-impact` in either mode. Classifier `high-impact-v1` is documented on the Invoke-policy ticket; overrides via `--high-impact-extra` / `--high-impact-except`.
_Avoid_: severity mode, aggression level, pentest mode

**High-impact tool**:
A tool (or analogous resource/prompt action) the Assessment must not Invoke without `--probe-high-impact`. Classification is the `high-impact-v1` heuristic on name/description/schema (exec/delete/write/egress/admin families, etc.) plus operator overrides.
_Avoid_: critical tool (severity of a Finding is separate)

**Judge**:
The operator-supplied model used to score tool / prompt / resource text for poisoning and related Checks. Every poisoning-class Check requires a Judge; there is no heuristics-only path for that class. Configured via `MCP_ASSESS_JUDGE_CMD` or `--judge-cmd` (flag wins): a shell command template with placeholders `{prompt_file}`, `{timeout_ms}`, `{check_id}`, `{subject_kind}`. Request is JSON on stdin (or `{prompt_file}`); response is the last JSON object on stdout (`verdict`, `score`, `rationale`, optional `severity_hint`). Missing Judge or Judge failure never counts as clean. Spec documents example templates for `llm` and Cursor Agent; neither is hard-required.
_Avoid_: classifier API, guardrail service (third-party hosted detectors are not the default Judge)

**Pin**:
A local baseline of Target tool / prompt / resource **definition hashes** (not full text) from a prior `--approve`, stored under `~/.mcp-assess/pins/` (overridable with `--pin-store`). Pin key = stable Target id plus Host Config path when local. First run without a Pin is informational only; hash drift emits Finding `PIN-DEFINITION-DRIFT`. Pins never auto-overwrite on drift.
_Avoid_: lockfile (unless you mean the on-disk Pin store file itself)

**Finding**:
A concrete result of a Check for a given Target, with severity (`low` / `medium` / `high` / `critical`), evidence, and citations to the frameworks the Check implements (OWASP MCP ID primary; ATLAS technique secondary when a fit exists). Report text redacts secrets by default (fingerprints / last-4); `--show-secrets` disables redaction.
_Avoid_: alert, hit, vulnerability (until confirmed — prefer Finding)

**Report**:
The artifact an Assessment produces: Surface Maps, Findings, and framework citations for that run — always as both markdown and JSON with the same content. JSON root: `schema_version`, `assessment`, `hosts`, `targets`, `surface_maps`, `findings`, `manual_checks`. Findings carry OWASP primary citations, optional ATLAS secondaries, optional short remediation, and redacted evidence by default.
_Avoid_: scan output, log, verdict (when you mean the whole artifact)

**Transport**:
How the Assessment client speaks to a Target: STDIO, SSE, or Streamable HTTP. All three are first-class in the destination.
_Avoid_: protocol (when you mean the wire binding — say Transport)
