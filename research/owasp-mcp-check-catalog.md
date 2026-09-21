# OWASP MCP Top 10 → mcp-assess v1 Check catalog

**Question:** What is the v1 Check catalog for `mcp-assess`, mapped from OWASP MCP01–MCP10? For each ID: Check id/name, automatable path (config / Enumerate / Invoke / Judge / manual), inputs, Finding shape, depth (deep vs light). Skew depth to MCP07 and MCP03.

**Vocabulary:** Assessment / Target / Host Config / Surface Map / Check / Finding / Invoke / Enumerate / Judge / Pin / Assessment Mode per repo `CONTEXT.md`.

**Scope:** Defensive Assessment Checks only. No exploit PoCs, payloads designed to compromise Targets, or attack playbooks. Invoke means authorized `tools/call` (or equivalent) under Assessment Mode gates.

---

## Summary

| OWASP ID | Official title (project Road Map) | Depth | v1 Checks (ids) |
| --- | --- | --- | --- |
| **MCP01:2025** | Token Mismanagement & Secret Exposure | light | `CFG-SECRETS-HOST`, `ENUM-SECRET-SCHEMA`, `MANUAL-TOKEN-HYGIENE` |
| **MCP02:2025** | Privilege Escalation via Scope Creep | light | `ENUM-OVERBROAD-SURFACE`, `MANUAL-SCOPE-DRIFT` |
| **MCP03:2025** | Tool Poisoning | **deep** | `JUDGE-TOOL-POISON`, `JUDGE-PROMPT-POISON`, `JUDGE-RESOURCE-POISON`, `ENUM-HIDDEN-CHARS`, `ENUM-TOOL-SHADOW`, `PIN-DEFINITION-DRIFT`, `ENUM-SCHEMA-SEMANTICS` |
| **MCP04:2025** | Software Supply Chain Attacks & Dependency Tampering | light | `CFG-UNPINNED-COMMAND`, `MANUAL-SUPPLY-CHAIN` |
| **MCP05:2025** | Command Injection & Execution | light | `ENUM-EXEC-CAPABILITY`, `MANUAL-SAFE-EXEC` |
| **MCP06:2025** | Prompt Injection via Contextual Payloads *(detail page: Intent Flow Subversion — see note)* | light | `JUDGE-INTENT-CONTEXT`, `MANUAL-INTENT-ANCHOR` |
| **MCP07:2025** | Insufficient Authentication & Authorization | **deep** | `CFG-MISSING-REMOTE-AUTH`, `ENUM-ANON-ACCESS`, `INVOKE-LIST-CALL-GAP`, `INVOKE-AUTHZ-ENFORCE`, `ENUM-TRANSPORT-AUTH`, `CFG-SHARED-STATIC-CREDS`, `MANUAL-IAM-MTLS` |
| **MCP08:2025** | Lack of Audit and Telemetry | light | `ENUM-LOGGING-CAP`, `MANUAL-TELEMETRY` |
| **MCP09:2025** | Shadow MCP Servers | light | `CFG-UNEXPECTED-TARGETS`, `MANUAL-SHADOW-INVENTORY` |
| **MCP10:2025** | Context Injection & Over-Sharing | light | `ENUM-BROAD-CONTEXT`, `MANUAL-CONTEXT-ISOLATION` |

**Depth policy:** MCP03 and MCP07 get multi-Check coverage (static + live + Judge/Pin where required). Every other ID gets at least one automatable Check **or** an explicit `manual` Report checklist slot.

**Naming note (MCP06):** The OWASP project Road Map / overview table labels MCP06 as *Prompt Injection via Contextual Payloads* ([OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)). The published detail document title and body are *Intent Flow Subversion* ([GitHub `MCP06-2025–Intent-Flow-Subversion.md`](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP06-2025%E2%80%93Intent-Flow-Subversion.md)). Cite **MCP06:2025** as the ID; prefer the detail-page title in Finding text and mention the Road Map alias once.

---

## Sources (primary)

| Source | Role |
| --- | --- |
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (also [projects/mcp-top-10](https://owasp.org/projects/mcp-top-10)) | Canonical list MCP01–MCP10 titles + overview blurbs |
| [OWASP/www-project-mcp-top-10 `2025/`](https://github.com/OWASP/www-project-mcp-top-10/tree/main/2025) | Per-ID detail pages (description, detect checklists, remediation) — cite per Check |
| [MCP Specification — Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) | Protocol-level auth / confused-deputy / transport guidance for MCP07 Checks |
| Repo `CONTEXT.md` | Assessment vocabulary, Judge requirement for poisoning-class Checks, Pin/Mode gates |

Individual OWASP detail files used below:

- [MCP01](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP01-2025-Token-Mismanagement-and-Secret-Exposure.md)
- [MCP02](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep.md)
- [MCP03](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP03-2025%E2%80%93Tool-Poisoning.md)
- [MCP04](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP04-2025%E2%80%93Software-Supply-Chain-Attacks%26Dependency-Tampering.md)
- [MCP05](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP05-2025%E2%80%93Command-Injection%26Execution.md)
- [MCP06](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP06-2025%E2%80%93Intent-Flow-Subversion.md)
- [MCP07](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md)
- [MCP08](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP08-2025%E2%80%93Lack-of-Audit-and-Telemetry.md)
- [MCP09](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP09-2025%E2%80%93Shadow-MCP-Servers.md)
- [MCP10](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP10-2025%E2%80%93ContextInjection%26OverSharing.md)

ATLAS secondary citations are **out of scope** here (see sibling ticket *Research ATLAS citation map*); Finding shape reserves an optional `atlas` field.

---

## Shared Finding shape (v1 proposal)

Every automatable Check emits zero or more Findings with this common envelope (exact Report schema is grilled elsewhere):

| Field | Notes |
| --- | --- |
| `check_id` | Stable id from this catalog (e.g. `INVOKE-LIST-CALL-GAP`) |
| `check_name` | Human title |
| `owasp` | Primary: `{ "id": "MCP07:2025", "title": "…", "url": "<OWASP detail or project URL>" }` |
| `atlas` | Optional secondary list — filled by ATLAS map ticket |
| `severity` | `low` \| `medium` \| `high` \| `critical` (`CONTEXT.md`) |
| `target_id` | Stable Target key (command/URL normalized; Host Config path when local) |
| `host_config_path` | Present when discovered from a Host Config |
| `evidence` | Check-specific object; **secrets redacted by default** (fingerprint / last-4) |
| `assessment_mode` | `safe` \| `unsafe` when the Check ran under Mode gates |
| `depth` | `deep` \| `light` |
| `status` | `finding` \| `informational` \| `manual_required` \| `skipped` (e.g. no Judge configured) |

Manual slots appear in the Report as checklist rows (`status: manual_required`) with the same `owasp` citation, even when no automated Finding fires.

---

## Automatable path legend

| Tag | Meaning |
| --- | --- |
| **config** | Static Host Config / local file inspection only |
| **Enumerate** | MCP list/describe methods (`tools/list`, `resources/list`, `prompts/list`, initialize/capabilities) — no mutating Invoke |
| **Invoke** | Authorized `tools/call` / `resources/read` under Assessment Mode; high-impact tools need explicit high-impact flag (`CONTEXT.md`) |
| **Judge** | Operator-supplied shell-out model scorer; **required** for every poisoning-class Check — no heuristics-only path (`CONTEXT.md`, map standing prefs) |
| **manual** | Report checklist for the operator; not claimed as automated detection |

---

## MCP01:2025 — Token Mismanagement & Secret Exposure

**OWASP claim:** Hard-coded credentials, long-lived tokens, and secrets in configs, logs, or model memory expose environments ([MCP01 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP01-2025-Token-Mismanagement-and-Secret-Exposure.md); detect checklist: tokens hard-coded in client/server/tool configs).

**Depth:** light

### `CFG-SECRETS-HOST` — Secrets in Host Config

| | |
| --- | --- |
| **Automatable** | config |
| **Inputs** | Discovered Host Config files; secret pattern pack (API keys, `Authorization` / bearer values, AWS-like keys, private-key PEM blocks) |
| **Finding evidence** | Path, JSON pointer / env key name, secret fingerprint (last-4), pattern class |
| **Severity default** | `high` (static credential in config); escalate if matches known cloud/admin key shapes |
| **Mode** | Safe |

### `ENUM-SECRET-SCHEMA` — Secret-like parameters in advertised schemas

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | `tools/list` / `prompts/list` schemas; names/descriptions mentioning token, password, api_key, secret |
| **Finding evidence** | Tool/prompt name, field name, matched cue (no live secret value unless returned — then redact) |
| **Severity default** | `low`–`medium` (hygiene / exposure risk signal) |
| **Mode** | Safe |

### `MANUAL-TOKEN-HYGIENE` — Token lifetime & rotation review

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Operator knowledge of vaulting, TTL, rotation (OWASP remediation: short-lived scoped tokens) |
| **Finding evidence** | Checklist answers only |
| **Mode** | n/a |

---

## MCP02:2025 — Privilege Escalation via Scope Creep

**OWASP claim:** Temporary or loosely defined permissions expand until agents hold excessive capabilities ([MCP02 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep.md)).

**Depth:** light

### `ENUM-OVERBROAD-SURFACE` — Over-broad / high-impact tool surface

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | Advertised tools; high-impact classifier (name/schema verbs — exact list grilled elsewhere); optional Pin for “surface grew” |
| **Finding evidence** | Tool names tagged high-impact; count of write/admin/exec-like tools; optional delta vs Pin |
| **Severity default** | `medium` when many high-impact tools with no documented scope constraint in schema annotations |
| **Mode** | Safe |

### `MANUAL-SCOPE-DRIFT` — Entitlement & expiry review

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Org IAM / agent scopes vs advertised tools (OWASP: no enforced expiration, shared service accounts) |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## MCP03:2025 — Tool Poisoning (**deep**)

**OWASP claim:** Compromised tools/plugins/outputs inject malicious or misleading context; sub-techniques include rug pulls, schema poisoning, and tool shadowing ([project overview](https://owasp.org/www-project-mcp-top-10/); [MCP03 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP03-2025%E2%80%93Tool-Poisoning.md)). Detail page also lists **static detection indicators**: model-directed imperatives, sensitive-path references, exfiltration patterns, zero-width/bidi characters, comment-smuggled instructions.

**Depth:** deep — Judge required for all poisoning-class semantic Checks (`CONTEXT.md`).

### `JUDGE-TOOL-POISON` — Tool description / schema text poisoning

| | |
| --- | --- |
| **Automatable** | Enumerate + **Judge** |
| **Inputs** | Each tool’s `name`, `description`, parameter descriptions; Judge prompt template; skip if Judge unset → `skipped` |
| **Finding evidence** | Tool name, excerpt (truncated), Judge score/label/rationale, OWASP static cue tags if also matched |
| **Severity default** | Judge-driven; map “clear imperative / exfil instruction” → `high`/`critical` |
| **Mode** | Safe |

### `JUDGE-PROMPT-POISON` — Prompt template poisoning

| | |
| --- | --- |
| **Automatable** | Enumerate + **Judge** |
| **Inputs** | `prompts/list` (+ `prompts/get` if needed under Enumerate/read policy) |
| **Finding evidence** | Prompt name, excerpt, Judge output |
| **Mode** | Safe |

### `JUDGE-RESOURCE-POISON` — Resource text as poisoned context

| | |
| --- | --- |
| **Automatable** | Enumerate + Invoke(`resources/read`) + **Judge** |
| **Inputs** | Resource URIs from `resources/list`; read under Safe unless marked high-impact/sensitive |
| **Finding evidence** | URI, excerpt, Judge output |
| **Mode** | Safe for list + low-risk reads; Unsafe/high-impact flag if resource class is sensitive |

### `ENUM-HIDDEN-CHARS` — Hidden / smuggled characters in declared surface

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | Tool/prompt/resource declaration strings; detectors for U+200B–200F, U+202A–202E, U+2060, U+FEFF; HTML/markdown comment blocks with model-directed text ([MCP03 detection indicators](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP03-2025%E2%80%93Tool-Poisoning.md)) |
| **Finding evidence** | Location, codepoints / comment span, surrounding excerpt |
| **Severity default** | `high` when paired with imperative language; else `medium` |
| **Mode** | Safe |
| **Note** | Mechanical detector OK; if also scoring “is this poisoning?”, still run `JUDGE-*` — do not replace Judge |

### `ENUM-TOOL-SHADOW` — Cross-server tool shadowing / name collision

| | |
| --- | --- |
| **Automatable** | Enumerate (multi-Target Assessment) |
| **Inputs** | Union of tools across Targets in one Assessment; Host Config server names |
| **Finding evidence** | Colliding tool names, Target ids, declaration hash mismatch summary |
| **Severity default** | `medium`–`high` when same name, different description/schema across Targets |
| **Mode** | Safe |

### `PIN-DEFINITION-DRIFT` — Rug-pull / trusted-definition drift

| | |
| --- | --- |
| **Automatable** | Enumerate + Pin store |
| **Inputs** | Current tool/prompt/resource definition hashes; Pin under `~/.mcp-assess` (or `--pin-store`); first run → informational “no Pin yet” |
| **Finding evidence** | Target Pin key, changed names, old/new hashes (not full text unless `--show-secrets` / verbose) |
| **Severity default** | `high` on unexpected drift of previously approved surface |
| **Mode** | Safe |
| **OWASP tie** | Rug pulls as MCP03 sub-technique ([tab / overview language](https://github.com/OWASP/www-project-mcp-top-10/blob/main/tab_top10.md); MCP03 detail scenarios on schema/manifest tampering) |

### `ENUM-SCHEMA-SEMANTICS` — Benign label vs destructive schema cues

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | Tool name/description vs parameter enums/verbs suggesting delete/exfil/admin |
| **Finding evidence** | Name vs schema cue mismatch list |
| **Severity default** | `medium` (hypothesis for Judge follow-up, not proof of malice) |
| **Mode** | Safe |

---

## MCP04:2025 — Software Supply Chain Attacks & Dependency Tampering

**OWASP claim:** Compromised SDKs/connectors/plugins alter agent behavior; vulnerable if floating versions, no signature/provenance, incomplete SBOM ([MCP04 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP04-2025%E2%80%93Software-Supply-Chain-Attacks%26Dependency-Tampering.md)).

**Depth:** light

### `CFG-UNPINNED-COMMAND` — Unpinned / mutable Target install refs

| | |
| --- | --- |
| **Automatable** | config |
| **Inputs** | Host Config `command`/`args` (e.g. `npx …@latest`, unpinned `uvx`/`pip` packages), URL Targets without integrity metadata |
| **Finding evidence** | Server entry, raw command/args, reason (`latest` / missing version pin) |
| **Severity default** | `medium` |
| **Mode** | Safe |

### `MANUAL-SUPPLY-CHAIN` — SBOM, signatures, registry trust

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Operator SBOM/signature/attestation review (OWASP prevent checklist) |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## MCP05:2025 — Command Injection & Execution

**OWASP claim:** Agents construct shell/API/code from untrusted input; tools wrapping `exec`/`system`/`shell=True` are high risk ([MCP05 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP05-2025%E2%80%93Command-Injection%26Execution.md)).

**Depth:** light — **no injection payload Invokes** in v1.

### `ENUM-EXEC-CAPABILITY` — Exec / shell / eval-looking tools

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | Tool names/descriptions/schemas matching shell, exec, run_command, eval, subprocess, bash, powershell, etc. |
| **Finding evidence** | Matching tools; tagged as high-impact candidates for Invoke policy |
| **Severity default** | `medium` (capability presence); does **not** claim confirmed injection |
| **Mode** | Safe |

### `MANUAL-SAFE-EXEC` — Parameterization & sandbox review

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Target implementation review against OWASP prevent list (no `shell=True`, allowlists, sandbox) |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## MCP06:2025 — Intent Flow Subversion (Road Map alias: Prompt Injection via Contextual Payloads)

**OWASP claim:** Malicious instructions in retrieved resources or tool outputs subvert the user’s intent in-flow ([MCP06 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP06-2025%E2%80%93Intent-Flow-Subversion.md)); Road Map still lists the prompt-injection-via-context title ([OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)).

**Depth:** light

### `JUDGE-INTENT-CONTEXT` — Goal-hijack instructions in retrieved context

| | |
| --- | --- |
| **Automatable** | Enumerate (+ `resources/read` as needed) + **Judge** |
| **Inputs** | Resource/prompt/tool-output text sampled under Mode; Judge rubric oriented to “overrides user goal / pivots to privileged action” (MCP06 scenarios) |
| **Finding evidence** | Source URI/tool, excerpt, Judge rationale |
| **Severity default** | Judge-driven |
| **Mode** | Safe |
| **Overlap** | Shares Judge plumbing with MCP03; Finding cites **MCP06** when the scored text is *retrieved context / output* steering intent, vs MCP03 when the *tool contract/description* itself is the poison |

### `MANUAL-INTENT-ANCHOR` — Intent anchoring / PDP / HITL controls

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Host/agent policy: goal anchoring, PDP allowlists, untrusted-context tagging ([MCP06 prevention](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP06-2025%E2%80%93Intent-Flow-Subversion.md)) |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## MCP07:2025 — Insufficient Authentication & Authorization (**deep**)

**OWASP claim:** Missing/optional API key validation, static shared secrets, client-side-only access control, tools that don’t validate caller identity/scope ([MCP07 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md)). Protocol guidance: [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) (authorization / confused-deputy / proxy patterns).

**Depth:** deep — detailed AuthZ pattern research may refine evidence fields (sibling ticket *Research MCP broken-authorization Check patterns*); this catalog locks the Check set.

### `CFG-MISSING-REMOTE-AUTH` — Remote Target without auth material in Host Config

| | |
| --- | --- |
| **Automatable** | config |
| **Inputs** | URL / SSE / Streamable HTTP Target entries; presence of `headers`, bearer, API key fields |
| **Finding evidence** | Host Config path, server name, transport URL (redact query secrets), “no auth headers/tokens configured” |
| **Severity default** | `high` for remote URL Targets with no auth fields |
| **Mode** | Safe |
| **OWASP** | Detect: missing/optional API key or token validation; insecure static credentials in config |

### `ENUM-ANON-ACCESS` — Unauthenticated session succeeds

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | Connect **without** operator-supplied credentials (and without Host Config secrets) to remote Target; observe initialize / `tools/list` success |
| **Finding evidence** | Transport, HTTP status / MCP error absence, methods allowed anonymously |
| **Severity default** | `critical` if tools/list (or call path) works with no auth on a non-loopback remote |
| **Mode** | Safe |
| **Constraint** | Only against operator-authorized Targets; STDIO local spawn is a different trust model — Report should note “process trust ≠ network auth” |

### `INVOKE-LIST-CALL-GAP` — List vs call authorization gap

| | |
| --- | --- |
| **Automatable** | Enumerate + Invoke |
| **Inputs** | Tools visible via `tools/list`; authorized probe `tools/call` with **schema-minimal / dry** arguments on **non–high-impact** tools in Safe; broader set in Unsafe; never use this Check to invent exploit payloads |
| **Finding evidence** | Tool name; list visibility; call result class (`allowed` / `denied` / `auth_error` / `validation_error`); credential profile used (anon vs configured) |
| **Severity default** | `high` when list succeeds under weak/anon identity but call unexpectedly succeeds for sensitive tools; `medium` when deny is inconsistent across similar tools |
| **Mode** | Safe (low-impact only); Unsafe expands tool set; high-impact still behind flag |

### `INVOKE-AUTHZ-ENFORCE` — Presentation vs execution enforcement

| | |
| --- | --- |
| **Automatable** | Invoke |
| **Inputs** | Tools whose schemas/descriptions claim restrictions (allowlists, “read-only”, role hints); compare claimed restriction to actual call outcome under the Assessment’s credential |
| **Finding evidence** | Claimed restriction excerpt, call outcome, credential profile |
| **Severity default** | `high` when execution ignores advertised restriction |
| **Mode** | Safe for read-only / low-impact; Unsafe otherwise |
| **OWASP** | “Authorization decisions rely on client input or context hints rather than server-side checks” |

### `ENUM-TRANSPORT-AUTH` — Transport / auth posture divergence

| | |
| --- | --- |
| **Automatable** | config + Enumerate |
| **Inputs** | Same logical Target reachable via multiple Transports or alternate URLs in Host Config; auth required on one path but not another |
| **Finding evidence** | Paths compared, auth required boolean per path |
| **Severity default** | `high` if any alternate path is weaker |
| **Mode** | Safe |

### `CFG-SHARED-STATIC-CREDS` — Shared or duplicated static secrets across Targets

| | |
| --- | --- |
| **Automatable** | config |
| **Inputs** | Env/header secret fingerprints across Host Config entries |
| **Finding evidence** | Matching fingerprint across server names (values redacted) |
| **Severity default** | `medium`–`high` |
| **Mode** | Safe |
| **OWASP** | Hard-coded shared secrets across agents; static credentials |

### `MANUAL-IAM-MTLS` — Org IAM / mTLS / RBAC review

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Operator confirmation of mTLS, OIDC/IAM integration, per-request RBAC/ABAC ([MCP07 prevent list](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md)) |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## MCP08:2025 — Lack of Audit and Telemetry

**OWASP claim:** Limited logging of tool invocations and context changes impedes IR; detect if tool invocations aren’t captured ([MCP08 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP08-2025%E2%80%93Lack-of-Audit-and-Telemetry.md)). Protocol: MCP logging utility capability ([MCP logging](https://modelcontextprotocol.io/specification/draft/basic/utilities/logging)).

**Depth:** light

### `ENUM-LOGGING-CAP` — Logging capability advertisement

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | Initialize / capabilities: logging support present or absent |
| **Finding evidence** | Capability blob excerpt; `informational` if absent (absence ≠ proof of no host-side logs) |
| **Severity default** | `low` / informational |
| **Mode** | Safe |

### `MANUAL-TELEMETRY` — Host & SIEM audit coverage

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Whether Host logs tool Invokes with identity, retention, SIEM forward (OWASP checklist) |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## MCP09:2025 — Shadow MCP Servers

**OWASP claim:** Unapproved MCP instances outside governance; if security cannot list all active MCP servers, shadow deployments exist ([MCP09 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP09-2025%E2%80%93Shadow-MCP-Servers.md)).

**Depth:** light — laptop Assessment discovers Host Config inventory, not enterprise network scan.

### `CFG-UNEXPECTED-TARGETS` — Host Config inventory vs allowlist

| | |
| --- | --- |
| **Automatable** | config |
| **Inputs** | All discovered Host Config Targets; optional operator allowlist / known-good registry file |
| **Finding evidence** | Targets not on allowlist; Host Config paths |
| **Severity default** | `medium` when allowlist provided; else informational inventory Finding |
| **Mode** | Safe |

### `MANUAL-SHADOW-INVENTORY` — Org-wide shadow discovery

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Network/CSPM/registry processes (OWASP detection: unregistered `/mcp` endpoints, etc.) — **outside** v1 CLI automation |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## MCP10:2025 — Context Injection & Over-Sharing

**OWASP claim:** Shared/persistent/underscoped context leaks data across users, agents, or tenants ([MCP10 detail](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP10-2025%E2%80%93ContextInjection%26OverSharing.md)).

**Depth:** light

### `ENUM-BROAD-CONTEXT` — Broad or sensitive-looking resources

| | |
| --- | --- |
| **Automatable** | Enumerate |
| **Inputs** | `resources/list` names/URIs/descriptions suggesting shared memory, multi-tenant stores, “all users”, transcripts, secrets |
| **Finding evidence** | Matching resources; hypothesis text (not proof of cross-tenant bleed) |
| **Severity default** | `low`–`medium` |
| **Mode** | Safe |

### `MANUAL-CONTEXT-ISOLATION` — Session / tenant isolation review

| | |
| --- | --- |
| **Automatable** | manual |
| **Inputs** | Architecture review: per-user namespaces, TTL, vector-store isolation ([MCP10 prevent](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP10-2025%E2%80%93ContextInjection%26OverSharing.md)) |
| **Finding evidence** | Checklist |
| **Mode** | n/a |

---

## Assessment Mode × Check matrix (v1)

| Check id | Safe | Unsafe | Needs Judge | Needs Pin | High-impact flag |
| --- | --- | --- | --- | --- | --- |
| `CFG-*` | yes | yes | no | no | no |
| `ENUM-*` (non-read) | yes | yes | no | optional | no |
| `JUDGE-TOOL-POISON` / `JUDGE-PROMPT-POISON` | yes | yes | **yes** | no | no |
| `JUDGE-RESOURCE-POISON` / `JUDGE-INTENT-CONTEXT` | yes* | yes | **yes** | no | if sensitive resource class |
| `PIN-DEFINITION-DRIFT` | yes | yes | no | **yes** | no |
| `INVOKE-LIST-CALL-GAP` | low-impact tools | broader | no | no | for high-impact tools |
| `INVOKE-AUTHZ-ENFORCE` | low-impact | broader | no | no | for high-impact tools |
| `MANUAL-*` | Report row | Report row | n/a | n/a | n/a |

\*Safe = Enumerate + low-risk `resources/read` only.

---

## Explicit non-goals (v1 Checks)

- No exploit PoCs, shell metacharacter payloads, or “prove RCE” Invokes (MCP05 stays Enumerate + manual).
- No interactive OAuth / device-code Assessment flows (map out of scope); bearer/header/Host Config pass-through only.
- No heuristics-only poisoning verdicts without Judge.
- No claim that missing MCP logging capability proves zero host telemetry (informational only).
- ATLAS technique IDs deferred to the ATLAS citation-map research ticket.

---

## Coverage checklist

| OWASP ID | ≥1 Check or manual slot? | Deep skew? |
| --- | --- | --- |
| MCP01 | yes (2 auto + 1 manual) | light |
| MCP02 | yes (1 auto + 1 manual) | light |
| MCP03 | yes (7 Checks) | **deep** |
| MCP04 | yes (1 auto + 1 manual) | light |
| MCP05 | yes (1 auto + 1 manual) | light |
| MCP06 | yes (1 Judge + 1 manual) | light |
| MCP07 | yes (6 auto + 1 manual) | **deep** |
| MCP08 | yes (1 auto + 1 manual) | light |
| MCP09 | yes (1 auto + 1 manual) | light |
| MCP10 | yes (1 auto + 1 manual) | light |
