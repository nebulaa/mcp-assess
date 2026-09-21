# ATLAS secondary citation map for MCP Findings

**Question:** Which MITRE ATLAS techniques (and case studies, if any) should `mcp-assess` Findings cite as secondary IDs when the primary ID is an OWASP MCP entry?

**Vocabulary:** Finding / Check / Target / Host Config / Invoke / Pin per repo `CONTEXT.md`. Primary Finding ID = OWASP MCP; ATLAS = secondary only when a clean fit exists.

**ATLAS snapshot researched:** collection version **2026.09** (modified 2026-09-15), loaded from the site-published dump [`ATLAS-2026.09.yaml`](https://atlas.mitre.org/atlas-data/dist/v6/ATLAS-2026.09.yaml) (also [`ATLAS-latest.yaml`](https://atlas.mitre.org/atlas-data/dist/ATLAS-latest.yaml), manifest [`manifest.yaml`](https://atlas.mitre.org/atlas-data/dist/manifest.yaml)). Source repo: [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data).

---

## Standing rules for Finding citations

1. **Primary ID is always OWASP MCP** (MCP01–MCP10). See [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and per-entry markdown under [OWASP/www-project-mcp-top-10/2025](https://github.com/OWASP/www-project-mcp-top-10/tree/main/2025).
2. **ATLAS has no MCP-named technique.** A full scan of technique `name` fields in ATLAS 2026.09 finds zero titles containing “MCP” or “Model Context Protocol.” MCP appears only inside descriptions (e.g. agent-tool / config techniques) and in case studies.
3. **Prefer agent-tool / tool-invocation / tool-exfiltration techniques** when choosing secondaries: especially [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053), [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) (+ sub-techniques), [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086), [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005), [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002).
4. **Omit ATLAS rather than stretch.** If the Check is about governance, telemetry absence, or a protocol AuthZ gap with no ATLAS peer, emit OWASP only (`no clean fit`).
5. **Case studies are optional enrichments**, not substitute technique IDs. Cite when the Finding class matches the case narrative (MCP-specific cases below).
6. **Deep-link form:** ATLAS YAML uses `/techniques/AML.T…` and `/case-studies/AML.CS…`. On atlas.mitre.org those paths are SPA routes (GitHub Pages serves the same shell as `/` / `404.html`); cite them as `https://atlas.mitre.org/techniques/<ID>` / `https://atlas.mitre.org/case-studies/<ID>`. Authoritative text remains the YAML dump above.

---

## Crosswalk (OWASP MCP → ATLAS)

| OWASP MCP (primary) | Recommended ATLAS secondary ID(s) | Fit notes | Optional case studies |
| --- | --- | --- | --- |
| **MCP01:2025** Token Mismanagement & Secret Exposure | **AML.T0083** Credentials from AI Agent Configuration; **AML.T0055** Unsecured Credentials; **AML.T0002.002** AI Agent Configuration; when secrets leave via tool Invoke: **AML.T0098** AI Agent Tool Credential Harvesting and/or **AML.T0086** Exfiltration via AI Agent Tool Invocation | T0002.002 / T0083 explicitly call out MCP Host Config shapes (`mcp.json`, `claude_desktop_config.json`). Prefer T0083 for Host Config secret Findings; T0055 for generic plaintext/env/store Findings; T0098/T0086 when an Assessment Invoke path shows tool-mediated credential collection/exfil. | [AML.CS0045](https://atlas.mitre.org/case-studies/AML.CS0045) (Cursor MCP → credential file exfil); [AML.CS0054](https://atlas.mitre.org/case-studies/AML.CS0054) (remote poisoned MCP tool harvests SSH / `mcp.json`) |
| **MCP02:2025** Privilege Escalation via Scope Creep | **AML.T0053** AI Agent Tool Invocation | Clean behavioral fit: ATLAS describes abusing agent-accessible tools for increased privileges / data access, including tools not directly available to the user. Do **not** cite ATT&CK-style “Valid Accounts” alone unless the Finding is literally stolen account use. | [AML.CS0037](https://atlas.mitre.org/case-studies/AML.CS0037) (agent tools used for broad data pull + email exfil) |
| **MCP03:2025** Tool Poisoning | **AML.T0110** AI Agent Tool Poisoning (**AML.T0110.000** Definition and Instructions; **AML.T0110.001** Implementation; **AML.T0110.002** Runtime Response); delivery/execution parents **AML.T0010.005** AI Agent Tool, **AML.T0011.002** Poisoned AI Agent Tool; rug-pull subclass **AML.T0109** AI Supply Chain Rug Pull; publish side **AML.T0115.002** AI Agent Tools | Strongest MCP-aligned cluster in ATLAS. T0110 description names MCP servers/tools. Map Check subtypes: schema/description/Judge poisoning → `.000`; malicious tool code/side effects → `.001`; tool output as injection → `.002`; Pin drift / post-adopt malicious update → T0109. | [AML.CS0053](https://atlas.mitre.org/case-studies/AML.CS0053) (poisoned Postmark MCP); [AML.CS0054](https://atlas.mitre.org/case-studies/AML.CS0054) (remote poisoned MCP tool) |
| **MCP04:2025** Software Supply Chain Attacks & Dependency Tampering | **AML.T0010** AI Supply Chain Compromise (esp. **AML.T0010.001** AI Software, **AML.T0010.005** AI Agent Tool); **AML.T0115** / **AML.T0115.002**; **AML.T0109** when update-after-trust | Prefer T0010.005 when the dependency *is* an MCP server/tool package or remote tool server; T0010.001 for generic AI/IDE extension packages. | AML.CS0053; AML.CS0049 (poisoned skill — adjacent agent-tool supply chain); AML.CS0047 (extension supply chain) |
| **MCP05:2025** Command Injection & Execution | **AML.T0050** Command and Scripting Interpreter; **AML.T0053** AI Agent Tool Invocation | Dual cite when shell/interpreter exposure is reached *through* agent tool Invoke (Assessment evidence of dangerous tool → command path). T0050 alone if the Finding is “Target exposes unsanitized command execution” without agent-tool framing. Avoid **AML.T0102** (Generate Malicious Commands) unless the Finding is about model-generated malware cmds, not MCP tool injection. | AML.CS0045 (prompt → `run_terminal_cmd`); AML.CS0046 (computer-use destruction via indirect injection) |
| **MCP06:2025** Intent Flow Subversion *(project roadmap / Top 10 table still labels this “Prompt Injection via Contextual Payloads”)* | **AML.T0051** LLM Prompt Injection + **AML.T0051.000** Direct / **AML.T0051.001** Indirect / **AML.T0051.002** Triggered; often paired with **AML.T0053** when injection’s effect is tool Invoke | Use sub-technique matching the Check: user/operator prompt → `.000`; tool/resource/web/retrieved context → `.001`; event/webhook/mail-triggered agent → `.002`. | AML.CS0045; AML.CS0054; AML.CS0020; AML.CS0059 |
| **MCP07:2025** Insufficient Authentication & Authorization | **no clean fit** for the AuthZ *gap itself* (list-vs-call, missing bearer validation, presentation-only allowlists). When a Finding’s evidence is *successful unauthorized or over-scoped tool Invoke*, add **AML.T0053**. For unauthenticated public-facing Target HTTP surfaces, optional adjacent **AML.T0049** Exploit Public-Facing Application. | ATLAS catalogs adversarial *behaviors*, not “broken ACL” weakness classes. Keep OWASP MCP07 primary; do not invent an ATLAS peer for list≠call. | none required; MCP AuthZ research note remains OWASP/MCP-spec anchored |
| **MCP08:2025** Lack of Audit and Telemetry | **no clean fit** | No ATLAS technique for missing audit logs / telemetry / immutable tool-invocation trails (search of 2026.09 descriptions). OWASP-only Finding. | — |
| **MCP09:2025** Shadow MCP Servers | **Partial — treat as no clean fit for the governance concept**; optional discovery secondaries **AML.T0006.000** Enumerate Hosted AI Resources, **AML.T0006.002** Scan for Exposed AI Infrastructure, **AML.T0002.002** AI Agent Configuration when the Check is “undeclared / unexpected MCP Host Config or exposed agent endpoint found” | “Shadow IT / unapproved MCP” is organizational. ATLAS discovery techniques cover *finding* exposed agent/MCP-like infra, not policy violation. Prefer OWASP-only unless the Finding is literally discovery of unexpected agent config/endpoints. | — |
| **MCP10:2025** Context Injection & Over-Sharing | **AML.T0057** LLM Data Leakage; context-payload path also **AML.T0051.001** Indirect; cross-tool leakage via Invoke **AML.T0086** | Over-sharing / cross-session context bleed → T0057. If the Check is poisoned *retrieved* context driving the model, cite T0051.001 (and MCP06 if dual-tagged). | AML.CS0021; AML.CS0035; AML.CS0040 (memory/context persistence themes) |

---

## Check-class quick map (beyond bare OWASP IDs)

Useful when a Finding’s Check class is named in product language rather than only MCP##:

| Check class (from `CONTEXT.md` / expected catalog) | Primary OWASP | ATLAS secondary |
| --- | --- | --- |
| Secrets in Host Config | MCP01 | AML.T0083, AML.T0002.002 (± AML.T0055) |
| List-vs-call / missing server AuthN / transport auth divergence | MCP07 | **no clean fit** (± AML.T0053 if unauthorized Invoke demonstrated) |
| Tool / prompt / resource poisoning (Judge-scored) | MCP03 | AML.T0110.000 / .002 as applicable |
| Cross-server tool shadowing / toxic flows | MCP03 (± MCP09 if undeclared server) | AML.T0110.000; shadow *server* governance → often OWASP-only |
| Pin drift / rug-pull | MCP03 / MCP04 | AML.T0109 + AML.T0110 / AML.T0010.005 |
| High-impact or mutate tool Invoke without gate | MCP02 / MCP05 | AML.T0053 (+ AML.T0050 if command/script) |
| Missing audit of tool invocations | MCP08 | **no clean fit** |

---

## Technique pocket guide (definitions from ATLAS 2026.09)

| ID | Name | Why it appears in this map |
| --- | --- | --- |
| [AML.T0002.002](https://atlas.mitre.org/techniques/AML.T0002.002) | AI Agent Configuration | Names MCP configs as credential/tool-definition sources. |
| [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005) | AI Agent Tool | Supply-chain compromise of agent tools; cites poisoned MCP server examples in description. |
| [AML.T0011.002](https://atlas.mitre.org/techniques/AML.T0011.002) | Poisoned AI Agent Tool | Victim invokes a poisoned tool (execution/user-execution tactic). |
| [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050) | Command and Scripting Interpreter | Command execution weakness class. |
| [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) (+ `.000`/`.001`/`.002`) | LLM Prompt Injection | Prompt / contextual payload injection. |
| [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | AI Agent Tool Invocation | Default secondary for over-scoped / unauthorized tool use. |
| [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055) | Unsecured Credentials | Insecure credential storage generally. |
| [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057) | LLM Data Leakage | Sensitive data elicited from model/context/connected sources. |
| [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083) | Credentials from AI Agent Configuration | Credentials taken from agent/tool config. |
| [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086) | Exfiltration via AI Agent Tool Invocation | Write-capable tools used to exfiltrate. |
| [AML.T0098](https://atlas.mitre.org/techniques/AML.T0098) | AI Agent Tool Credential Harvesting | Using agent tools to collect credentials. |
| [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109) | AI Supply Chain Rug Pull | Malicious update after adoption (Pin-relevant). |
| [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110) (+ `.000`/`.001`/`.002`) | AI Agent Tool Poisoning | Canonical tool-poisoning technique; MCP called out in text. |
| [AML.T0115.002](https://atlas.mitre.org/techniques/AML.T0115.002) | Publish Poisoned AI Artifacts: AI Agent Tools | Publishing poisoned MCP/tools to hubs/registries. |

---

## MCP-relevant ATLAS case studies (optional Report links)

| ID | Name | Techniques employed (selected) |
| --- | --- | --- |
| [AML.CS0045](https://atlas.mitre.org/case-studies/AML.CS0045) | Data Exfiltration via an MCP Server used by Cursor | T0051.001, T0053, T0083, T0086, … |
| [AML.CS0053](https://atlas.mitre.org/case-studies/AML.CS0053) | Poisoned Postmark MCP Server Email Exfiltration | T0010.005, T0011.002, T0110.001, T0109, T0086, T0115.002, … |
| [AML.CS0054](https://atlas.mitre.org/case-studies/AML.CS0054) | Data Exfiltration via Remote Poisoned MCP Tool | T0010.005, T0110.000, T0051.001, T0053, T0055, T0086, T0098, … |

Relationship `employs` edges are in the same ATLAS YAML under `relationships.<case-id>.employs`.

---

## Sources

| Source | Role |
| --- | --- |
| [MITRE ATLAS](https://atlas.mitre.org/) | Framework home (2026.09: 16 tactics / 197 techniques / 72 case studies per site counters at research time). |
| [ATLAS-2026.09.yaml](https://atlas.mitre.org/atlas-data/dist/v6/ATLAS-2026.09.yaml) | Primary machine-readable definitions + case-study technique links. |
| [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data) | Upstream data repository. |
| [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) | Primary Finding taxonomy (MCP01–MCP10). |
| [OWASP MCP Top 10 entries (GitHub 2025/)](https://github.com/OWASP/www-project-mcp-top-10/tree/main/2025) | Per-ID descriptions used for semantic mapping. |

**Uncertainty:** OWASP entry **MCP06** filename/title in-repo is “Intent Flow Subversion,” while the project overview table still says “Prompt Injection via Contextual Payloads.” This map treats MCP06 as the prompt/context-injection class (AML.T0051). Revisit if OWASP renames or splits the entry.
