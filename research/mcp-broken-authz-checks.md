# MCP broken-authorization Assessment Checks

Defensive Check patterns for detecting insufficient authentication and authorization on MCP Targets. Vocabulary follows repo `CONTEXT.md` (Assessment Mode Safe/Unsafe, Enumerate, Invoke, high-impact). Primary framework ID: **OWASP MCP07:2025 – Insufficient Authentication & Authorization**. Related: **MCP02** (scope creep / over-broad tool reach) when list filters are treated as least-privilege boundaries.

**Scope of this note:** Check signals and mode constraints only. No exploit procedures, payloads, or attack playbooks.

---

## Framework and spec anchors

| Source | What it establishes for Checks |
| --- | --- |
| [OWASP MCP07](https://owasp.org/www-project-mcp-top-10/) / [MCP07 markdown](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md) | Missing/optional token validation; authz that relies on client-side or presentation-only enforcement; tools that do not validate identity/scope before execution; deny-by-default server-side checks. |
| [OWASP MCP02](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep.md) | Over-broad tool reach when operator “allow” config is trusted as a privilege boundary. |
| [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | HTTP transports: OAuth 2.1 resource-server posture; Bearer on every request; 401 vs 403; audience/`resource` binding (RFC 8707); authorization OPTIONAL but when used MUST follow the spec. STDIO SHOULD use env credentials, not this OAuth flow. |
| [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) | Token passthrough forbidden; confused-deputy controls for proxy servers; **“MCP servers SHOULD bind session IDs to user-specific information.”** |
| [MCP Transports (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | Streamable HTTP session via `MCP-Session-Id`; servers SHOULD implement proper authentication; Origin validation / localhost binding for local HTTP. |

---

## Shared Assessment rules for all AuthZ Checks

1. **Honor-system Target only** — operator asserts authorization to Assess the Target.
2. **Enumerate ≠ authorization** — `tools/list` (and analogous list methods) is discovery; enforcement must be re-validated on `tools/call` (and `resources/*` / `prompts/get` where applicable).
3. **Safe vs Unsafe** (from `CONTEXT.md`):
   - **Safe:** Host Config static Checks + Enumerate + AuthZ probes + Invoke of **low-impact** tools.
   - **Unsafe:** Safe plus broader Invoke (mutate-looking tools, alternate transports/paths).
   - **High-impact tools:** never Invoked unless the explicit high-impact probe flag is set (even in Unsafe).
4. **Finding evidence:** redact secrets by default; record method outcomes (status / error class), list membership diffs, and Host Config key names — not raw tokens.
5. **Secondary citations:** ATLAS has no MCP-named technique; prefer agent-tool / unauthorized tool-use techniques when the ATLAS research ticket lands. Primary ID remains OWASP MCP07 (or MCP02 where noted).

---

## Pattern catalog

### 1. List-vs-call gap (presentation filter ≠ execution gate)

**Weakness class:** Tool (or resource/prompt) filtering applied only at discovery (`tools/list`) while execution (`tools/call`) resolves against the full registry. Documented as the core failure in multiple advisories (“cosmetic” access control).

**Canonical citations:**
- [CVE-2026-46519](https://www.cve.org/CVERecord?id=CVE-2026-46519) / [GHSA-cr22-wjx7-2w6m](https://github.com/Flux159/mcp-server-kubernetes/security/advisories/GHSA-cr22-wjx7-2w6m) — `ALLOW_ONLY_READONLY_TOOLS`, `ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS`, `ALLOWED_TOOLS` enforced on list, not call (fixed ≥ 3.6.0).
- [GHSA-3r68-hf9h-887v](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-3r68-hf9h-887v) (CVE-2026-77243 reserved/reported in coordinator write-ups) — `ENABLED_TOOLS` / `TOOLSETS` list-only; call path used unfiltered registry (fixed ≥ 0.22.0). Advisory notes `READ_ONLY_MODE` had dual enforcement — the correct pattern.
- [googleapis/mcp-toolbox#2755](https://github.com/googleapis/mcp-toolbox/issues/2755) — toolset-scoped URL filters list membership; call resolves tools globally (and analogous `prompts/get` issue). Treat as the same Check shape pending advisory/CVE if published.

**OWASP:** MCP07 (primary); MCP02 when the filter was the operator’s least-privilege boundary.

#### Signals

| Stage | What to observe |
| --- | --- |
| **Host Config** | Env/args naming allowlists or modes: `ALLOWED_TOOLS`, `ENABLED_TOOLS`, `TOOLSETS`, `ALLOW_ONLY_*`, `READ_ONLY*`, toolset path segments in URLs. Document which keys claim to restrict tools. |
| **Enumerate** | `tools/list` returns a subset smaller than the product’s known full catalog (or smaller than Host Config’s implied universe). Record the advertised name set *L*. |
| **Authorized Invoke** | Under operator authorization, attempt `tools/call` for a name in the **configured-excluded** or **not-in-*L*** set that is still a plausible registered tool for that Target (from Host Config complement, package docs, or a prior unfiltered Pin — not from blind guessing across the internet). Expected secure outcome: authorization/unknown-tool denial consistent with list policy. Finding if call **executes** or returns a success-class result for a tool absent from *L* / outside the allowlist. |

Same shape for `resources/list` vs `resources/read` and `prompts/list` vs `prompts/get` when Host Config or URL scoping claims a set boundary (mcp-toolbox-style).

#### Mode and high-impact

| Mode | Allowed probe |
| --- | --- |
| **Safe** | Config + Enumerate always. AuthZ Invoke only for **low-impact** excluded names (read/echo/search-class). If the only excluded names are high-impact, emit a **manual / gated** Finding candidate: “list filter present; call-time enforcement not verified for high-impact names.” |
| **Unsafe** | May Invoke mutate-looking excluded tools that are **not** high-impact. |
| **High-impact flag** | Required before Invoking excluded tools classified high-impact (e.g. delete/exec/admin verbs). Prefer minimal arguments and Targets the operator designates as disposable. |

**Check id (suggested):** `mcp07.list-vs-call-tools` (+ optional `mcp07.list-vs-call-resources`, `mcp07.list-vs-call-prompts`).

---

### 2. Cosmetic allowlists (documented ACL, list-only enforcement)

**Weakness class:** Operator-facing configuration advertised as access control, but enforcement is presentation-only. Subset of pattern 1 with a stronger **config-documentation** signal — Host Config keys are the ACL story.

**Canonical citations:** Same as pattern 1; GHSA-cr22-wjx7-2w6m literally calls the control “effectively cosmetic.” Manifold analysis of mcp-atlassian frames `ENABLED_TOOLS` as an allowlist that only hid the menu ([manifold.security write-up](https://www.manifold.security/blog/mcp-atlassian-access-control-bypass) citing GHSA-3r68-hf9h-887v).

**OWASP:** MCP07; MCP02 for “restricted deployment that wasn’t.”

#### Signals

| Stage | What to observe |
| --- | --- |
| **Host Config** | Presence of allowlist/mode env vars **and** language in Target docs/README claiming restriction. Flag HTTP/SSE/Streamable remote Targets especially (advisories stress multi-client HTTP). |
| **Enumerate** | List reflects the allowlist (negative control that the filter *exists*). |
| **Authorized Invoke** | Identical to pattern 1: call-time must re-apply the same predicate. Also note **reachability auth without per-tool auth** (e.g. shared `MCP_AUTH_TOKEN` / `X-MCP-AUTH` gates who connects but not which tools — called out in GHSA-cr22-wjx7-2w6m). |

#### Mode and high-impact

Same as pattern 1. **Safe** static Finding is warranted when Host Config shows allowlist keys on a remote HTTP Target **even before Invoke**, severity raised after confirmed list-vs-call gap.

**Check id (suggested):** `mcp07.cosmetic-allowlist` (may alias or compose with `mcp07.list-vs-call-tools`).

---

### 3. Transport / auth divergence (session routing decoupled from principal)

**Weakness class:** HTTP session affinity (`session_id` / `Mcp-Session-Id`) is used as the sole authorization key for routing JSON-RPC after (or beside) bearer auth. Auth middleware and session lookup never cross-check — a different authenticated principal (or, in some SDK bugs, an unauthenticated holder of the ID) can act on another session.

**Canonical citations:**
- Spec: [Security Best Practices – Session Hijacking](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) — servers **SHOULD bind session IDs to user-specific information**.
- Spec: [Transports – Session Management](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) — `MCP-Session-Id` lifecycle; auth is separate SHOULD.
- [CVE-2026-52869](https://nvd.nist.gov/vuln/detail/CVE-2026-52869) / [GHSA-jpw9-pfvf-9f58](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-jpw9-pfvf-9f58) — Python SDK SSE + stateful Streamable HTTP routed by session id only; fixed in mcp ≥ 1.27.2 by binding client_id + issuer/subject.
- [CVE-2026-33946](https://www.cve.org/CVERecord?id=CVE-2026-33946) / [GHSA-qvqr-5cv7-wh35](https://github.com/advisories/GHSA-qvqr-5cv7-wh35) — Ruby SDK Streamable HTTP SSE stream hijack via session id replay; lack of session-to-user binding (fixed ≥ 0.9.2).

**OWASP:** MCP07 (authn/authz isolation failure); CWE-639 class in the CVEs.

#### Signals

| Stage | What to observe |
| --- | --- |
| **Host Config** | Remote URL Target; SDK/package version pins if present; auth headers/env vs “no auth.” Stateful Streamable HTTP / legacy SSE. |
| **Enumerate** | Session id returned on initialize; subsequent Enumerate requires `Mcp-Session-Id`. Note whether unauthenticated Enumerate succeeds (also feeds pattern 4). |
| **Authorized Invoke** | **Do not** invent stolen session IDs in Assessments. Prefer: (a) **version/advisory Check** against known affected SDK ranges when the Target’s dependency is visible; (b) **manual checklist** when two operator-owned principals exist — confirm a second authorized credential cannot attach to the first session’s id; (c) Safe observation that auth is enabled but session responses do not vary by principal claims (inconclusive alone). |

#### Mode and high-impact

| Mode | Allowed probe |
| --- | --- |
| **Safe** | Config/version advisory match; Enumerate session behavior; manual checklist rows. No cross-principal session injection scripts. |
| **Unsafe** | Optional dual-credential **operator-owned** correlation test if the product explicitly supports multi-user Assessment fixtures — still no opportunistic session-ID hunting. |
| **High-impact** | Any tool Invoked on a foreign session inherits high-impact rules; prefer deny/404 observation over successful tool execution. |

**Check id (suggested):** `mcp07.session-principal-binding` (config/advisory + manual); `mcp07.transport-auth-divergence` as the umbrella Finding class.

---

### 4. Missing or optional server authentication

**Weakness class:** HTTP MCP endpoint accepts protocol traffic without Bearer/OAuth (or with optional auth). Spec: authorization is OPTIONAL, but unprotected remote endpoints enable unauthenticated Enumerate and often unauthenticated Invoke. OWASP MCP07 lists missing/optional API key validation and “disable guest/anonymous access.”

**Canonical citations:**
- [MCP Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) — OPTIONAL; when HTTP auth is used, conform to OAuth 2.1 resource-server rules; STDIO uses env credentials.
- [Transports security warning](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) — servers SHOULD implement proper authentication; bind localhost when local.
- OWASP MCP07 vulnerable checklist — missing mutual auth / guest access / static long-lived tokens.
- Ecosystem measurement cited by OWASP MCP07 references (~38% of scanned servers lacking protocol-level auth in secondary write-ups) — use as context, not as a Finding by itself.

**OWASP:** MCP07 (primary); MCP01 if secrets are absent because nothing is required (adjacent).

#### Signals

| Stage | What to observe |
| --- | --- |
| **Host Config** | `url` / SSE / Streamable Target with no `Authorization`, header map, or auth-related env. Contrast STDIO Targets that inject tokens via env (expected for STDIO per spec). |
| **Enumerate** | `initialize` / `tools/list` succeed with **no** credentials on a non-loopback URL → Finding. Loopback-only may be lower severity but still reportable if Origin/DNS-rebinding controls are missing (transport SHOULD). |
| **Authorized Invoke** | Safe: low-impact `tools/call` without credentials if Enumerate already proved open access — confirms execution path is also ungated. Do not escalate to high-impact without the flag. |

#### Mode and high-impact

| Mode | Allowed probe |
| --- | --- |
| **Safe** | Full Check for missing auth via Enumerate; optional low-impact unauthenticated Invoke. |
| **Unsafe** | Broader unauthenticated Invoke still bounded by high-impact flag. |
| **High-impact** | Required for destructive tools even when the Target is openly unauthenticated (blast radius is the point of the Finding). |

**Check id (suggested):** `mcp07.missing-server-auth`; companion `mcp07.auth-optional` when 401 is inconsistent across methods.

---

### 5. Auth present but no per-tool / per-scope enforcement

**Weakness class:** Successful network authentication (shared API key, single Bearer) is treated as sufficient for **all** tools. Distinct from cosmetic allowlists: there may be **no** tool filter at all, or filters that only affect UX. OWASP MCP07: evaluate permissions per request; tools must validate scopes; RBAC/ABAC deny-by-default.

**Canonical citations:**
- OWASP MCP07 — “Tool endpoints don’t validate permission scopes”; “Authorization decisions rely on client input.”
- GHSA-cr22-wjx7-2w6m — `MCP_AUTH_TOKEN` authenticates the client but provides no per-tool authorization.
- [MCP Authorization error handling](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) — 403 / `insufficient_scope` for runtime scope failures (when OAuth scopes are in play).

**OWASP:** MCP07; MCP02 when one token implies admin-equivalent tool surface.

#### Signals

| Stage | What to observe |
| --- | --- |
| **Host Config** | Single shared secret/token; no scope/role env; all tools effectively available to any authenticated Host. |
| **Enumerate** | Full privileged tool catalog visible to a minimally privileged Assessment credential (if operator can supply a “low” token). |
| **Authorized Invoke** | With a **reduced-scope** operator credential (when available), Invoke tools that should be out of scope. Finding if success. If only one credential exists, Check is **manual**: document shared-token blast radius from Surface Map. |

#### Mode and high-impact

Prefer Safe Enumerate + config. Scope-boundary Invokes follow the same Safe/Unsafe/high-impact matrix as pattern 1.

**Check id (suggested):** `mcp07.auth-without-tool-authz`.

---

### 6. Token audience / passthrough divergence (spec anti-patterns)

**Weakness class:** Server accepts tokens not issued for itself, and/or forwards client tokens upstream (token passthrough). Spec forbids passthrough; requires audience binding via RFC 8707 `resource` / `aud`.

**Canonical citations:**
- [MCP Authorization – Access Token Privilege Restriction](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [Security Best Practices – Token Passthrough](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- OWASP MCP07 — validate every token server-side; never trust client-provided claims.

**OWASP:** MCP07 (primary).

#### Signals

| Stage | What to observe |
| --- | --- |
| **Host Config** | Proxy-style Targets; shared upstream tokens in env; absence of audience/resource configuration. |
| **Enumerate** | Protected Resource Metadata / `WWW-Authenticate` presence (discovery of intended AS). Missing metadata on a “secured” HTTP Target is a weak signal, not proof of passthrough. |
| **Authorized Invoke** | Mostly **manual / Unsafe-gated** with operator-supplied wrong-audience tokens **only when the operator owns both token issuers**. Automated Checks should not mint or steal foreign tokens. Prefer checklist + dependency/docs review. |

#### Mode and high-impact

**Safe:** config + metadata Enumerate + manual checklist. **Unsafe:** operator-owned wrong-audience probe if explicitly enabled. High-impact rules still apply to any successful tool execution.

**Check id (suggested):** `mcp07.token-audience-validation` (manual-heavy); `mcp07.token-passthrough` (manual).

---

## Mode matrix (summary)

| Check pattern | Host Config | Enumerate | Invoke | Default mode | High-impact constraint |
| --- | --- | --- | --- | --- | --- |
| List-vs-call / cosmetic allowlist | Allowlist keys | Diff *L* vs claimed set | Call excluded name | Safe for low-impact probes | Flag required for high-impact excluded tools |
| Transport/auth divergence | URL + SDK hints | Session header behavior | Dual-principal / version match | Safe = advisory + manual | Avoid executing high-impact tools on foreign sessions |
| Missing server auth | No auth material on URL Target | Unauth list succeeds | Optional low-impact unauth call | Safe | Flag for destructive tools |
| Auth without tool authz | Shared token | Full catalog on weak cred | Out-of-scope call | Safe Enumerate; Invoke if dual creds | Same as list-vs-call |
| Audience / passthrough | Proxy/env clues | PRM / WWW-Authenticate | Manual wrong-aud token | Safe manual | Same |

---

## Implementation notes for the future spec (not product work)

1. **AuthZ probe ≠ fuzzing:** only names justified by Host Config, advertised catalogs, Pins, or Target package documentation the Assessment already resolved.
2. **Negative control first:** prove the list filter works (`tools/list`) before claiming a call-time bypass — mirrors advisory methodology without reproducing their PoC payloads.
3. **STDIO vs HTTP:** missing OAuth on STDIO is normal (spec); missing any credential gating on **remote HTTP** is the Finding. Cosmetic allowlists matter most on multi-client HTTP.
4. **Compose Findings:** one Target may hit MCP07 list-vs-call **and** MCP07 missing auth; keep Check ids distinct in the Report.
5. **Pin interaction:** a Pin from an unfiltered Assessment can supply the “full catalog” baseline for later filtered Assessments (list-vs-call without relying on external docs).

---

## Sources (primary)

1. OWASP MCP Top 10 — [MCP07](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md), [MCP02](https://github.com/OWASP/www-project-mcp-top-10/blob/main/2025/MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep.md)
2. MCP spec — [Authorization 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), [Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices), [Transports 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
3. Advisories/CVEs — [CVE-2026-46519](https://www.cve.org/CVERecord?id=CVE-2026-46519) / [GHSA-cr22-wjx7-2w6m](https://github.com/Flux159/mcp-server-kubernetes/security/advisories/GHSA-cr22-wjx7-2w6m); [GHSA-3r68-hf9h-887v](https://github.com/sooperset/mcp-atlassian/security/advisories/GHSA-3r68-hf9h-887v); [CVE-2026-52869](https://nvd.nist.gov/vuln/detail/CVE-2026-52869) / [GHSA-jpw9-pfvf-9f58](https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-jpw9-pfvf-9f58); [CVE-2026-33946](https://www.cve.org/CVERecord?id=CVE-2026-33946) / [GHSA-qvqr-5cv7-wh35](https://github.com/advisories/GHSA-qvqr-5cv7-wh35); [mcp-toolbox#2755](https://github.com/googleapis/mcp-toolbox/issues/2755)
