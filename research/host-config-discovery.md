# Host Config discovery — Cursor, Claude Desktop, VS Code

**Question:** Where and in what shapes do Cursor, Claude Desktop, and VS Code store Host Configs on macOS, Linux, and Windows? Paths, Assessment-relevant schema fields, multi-file layouts, and stable Target id derivation.

**Vocabulary:** Host / Host Config / Target per repo `CONTEXT.md`.

**Scope:** Local file Host Configs discoverable on the operator’s machine. Interactive OAuth / cloud-brokered connectors are noted only where they affect what a local Assessment can see.

---

## Summary

| Host | Global / user Host Config | Project / workspace Host Config | Root key | Local spawn | Remote connect |
| --- | --- | --- | --- | --- | --- |
| **Cursor** | `~/.cursor/mcp.json` | `<project>/.cursor/mcp.json` | `mcpServers` | `command` / `args` / `env` (+ `envFile`) | `url` / `headers` (+ optional `auth`) |
| **Claude Desktop** | `claude_desktop_config.json` under OS app-support dir (see below) | none documented | `mcpServers` | `command` / `args` / `env` | **not** in that file — Connectors UI / account |
| **VS Code** | user-profile `mcp.json` (via MCP: Open User Configuration) | `.vscode/mcp.json` | `servers` | `command` / `args` / `env` / `cwd` / `envFile` | `type` `http`\|`sse` + `url` / `headers` |

---

## Cursor

### Paths

First-party docs ([Cursor MCP](https://cursor.com/docs/mcp), [MCP help](https://cursor.com/help/customization/mcp)):

| Scope | Path |
| --- | --- |
| Project | `.cursor/mcp.json` at project root |
| Global | `~/.cursor/mcp.json` in the home directory |

**Windows:** Cursor’s docs write `~/.cursor/mcp.json` only. Home on Windows is the user profile, so the practical path is `%USERPROFILE%\.cursor\mcp.json`. That expansion is consistent with Cursor staff on the [forum](https://forum.cursor.com/t/editing-mcp-json/169933) and with VS Code’s discovery table (below). **Uncertainty:** Cursor docs do not spell `%USERPROFILE%` explicitly.

**Linux / macOS:** `~/.cursor/mcp.json` as documented.

VS Code’s first-party discovery table also lists Cursor global as `~/.cursor/mcp.json` and workspace as `<project>/.cursor/mcp.json` ([MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)).

### Multi-file layout

- Two files: global + project.
- Both are merged; if the same server **name** appears in both, **project wins** ([MCP help](https://cursor.com/help/customization/mcp)).
- No other Cursor Host Config filenames are documented for local Assessment discovery. Team Marketplace / Cloud Agent dashboard configs are remote/admin surfaces — out of local file discovery unless later specified.

### Schema fields (Assessment-relevant)

Root object: `mcpServers` → map of name → server object.

**STDIO (local):** documented fields ([Cursor MCP — STDIO server configuration](https://cursor.com/docs/mcp)):

| Field | Required (per STDIO table) | Role |
| --- | --- | --- |
| `type` | Yes (`"stdio"`) | Transport hint |
| `command` | Yes | Executable |
| `args` | No | Argument array |
| `env` | No | Environment map |
| `envFile` | No | Env file path (STDIO only) |

**Note / uncertainty:** Many Cursor examples omit `type` and use only `command`/`args`/`env`. Treat missing `type` + presence of `command` as STDIO for discovery; do not require `type` to accept an entry.

**Remote (HTTP / SSE):** examples use `url` and optional `headers`; transport table lists `stdio`, `SSE`, and `Streamable HTTP` ([Cursor MCP](https://cursor.com/docs/mcp)). Optional static OAuth block `auth` with `CLIENT_ID`, `CLIENT_SECRET`, `scopes` for remote `url` entries.

**Interpolation** (resolved by Cursor, still present as strings on disk): `${env:NAME}`, `${userHome}`, `${workspaceFolder}`, `${workspaceFolderBasename}`, `${pathSeparator}` / `${/}` — applied to `command`, `args`, `env`, `url`, `headers`.

---

## Claude Desktop

### Paths (local STDIO Host Config)

Official MCP “connect local servers” guide ([modelcontextprotocol.io](https://modelcontextprotocol.io/docs/develop/connect-local-servers)):

| OS | Path |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

That same guide states Claude Desktop is available for **macOS and Windows** (not Linux) in prerequisites.

**Linux path (secondary first-party, product-caveat):**

| Source | Path |
| --- | --- |
| VS Code discovery table | `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json`, or `~/.config/Claude/claude_desktop_config.json` if unset ([MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)) |
| MCP Python SDK `get_claude_config_path()` | same XDG layout under `…/Claude`, file `claude_desktop_config.json` ([python-sdk `claude.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/cli/claude.py)) |

**Uncertainty:** Anthropic’s local-servers doc does not document a Linux Desktop install. Prefer discovering the Linux path if the file exists (for unofficial ports / future support); do not assume Claude Desktop is installed on Linux from Anthropic docs alone.

**Windows Store / MSIX alternate AppData:** community reports cite package-scoped Roaming under `%LOCALAPPDATA%\Packages\…`. **Not** confirmed in Anthropic or MCP official path tables — mark **uncertain**; optional secondary probe only if the standard `%APPDATA%\Claude\…` file is missing.

### Multi-file layout

- Single machine-wide Host Config file for local MCP servers.
- No project-scoped Claude Desktop Host Config in first-party docs.
- File may be created empty/`{}` on first “Edit Config”; `mcpServers` added by the operator.

### Schema fields (Assessment-relevant)

Root: `mcpServers` → name → object.

Documented / exemplified fields:

| Field | Evidence | Role |
| --- | --- | --- |
| `command` | MCP local-servers examples | Executable |
| `args` | same | Argument array |
| `env` | Windows troubleshooting example (`APPDATA`, API keys) | Environment map |

Optional `type: "stdio"` appears in Anthropic Claude Code docs when showing a Desktop entry; **not** required in the core Desktop filesystem tutorial.

**Remote Targets:** Anthropic Help Center states remote / custom connectors are added via **Customize → Connectors** (URL + optional OAuth client id/secret), and that Claude connects from **Anthropic’s cloud**, not the local device. Local `claude_desktop_config.json` is a **separate** mechanism for local STDIO servers ([custom connectors](https://support.anthropic.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp)). Indonesian Anthropic help text states Desktop will **not** connect to remotes configured only in `claude_desktop_config.json`.

**Implication for Assessment:** local Host Config discovery on Claude Desktop covers STDIO Targets only. Remote connector URLs are account/UI state — **not** a documented local JSON Host Config for v1 file discovery. Mark remote Claude Desktop Targets as out-of-band unless a later ticket finds an on-disk cache.

---

## VS Code

### Paths

First-party ([Add and manage MCP servers](https://code.visualstudio.com/docs/copilot/customization/mcp-servers), [MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)):

| Scope | Documented location |
| --- | --- |
| Workspace | `.vscode/mcp.json` |
| User profile | `mcp.json` opened by **MCP: Open User Configuration** (under the user profile folder) |
| Remote user | **MCP: Open Remote User Configuration** (remote environment’s `mcp.json`) |
| Agent Host portable (extra) | workspace `.mcp.json`; user `~/.copilot/mcp-config.json` (or `$COPILOT_HOME/mcp-config.json`) |

**Absolute user-profile paths** are **not** spelled in the MCP articles. They follow VS Code’s standard user-data `User` directory + filename `mcp.json`:

| OS | Inferred user Host Config path |
| --- | --- |
| macOS | `~/Library/Application Support/Code/User/mcp.json` |
| Windows | `%APPDATA%\Code\User\mcp.json` |
| Linux | `~/.config/Code/User/mcp.json` (respect `XDG_CONFIG_HOME`) |

**Uncertainty:** inferred from VS Code user-data layout + documented filename; confirm with “Open User Configuration” on a reference install if a Check depends on the absolute path. Variants (**Code - Insiders**, **VSCodium**, Cursor-as-VS-Code-fork) use different product-dir names — out of v1 default list unless expanded later.

Dev Containers may materialize remote `mcp.json` from `customizations.vscode.mcp` in `devcontainer.json` ([same manage doc](https://code.visualstudio.com/docs/copilot/customization/mcp-servers)).

### Multi-file layout

- At least: user `mcp.json` + per-workspace `.vscode/mcp.json`.
- Optional Agent Host–native: `.mcp.json`, `~/.copilot/mcp-config.json`.
- Enable/disable state is stored **separately** from `mcp.json` (does not rewrite shared config).
- Autodiscovery can also **read** other Hosts’ files (Claude Desktop, Cursor, Windsurf, Copilot CLI) when `chat.mcp.discovery.enabled` sources are on — useful cross-check, not a substitute for scanning those paths directly.

### Schema fields (Assessment-relevant)

Root differs from Cursor/Claude: **`servers`** (not `mcpServers`). Optional siblings: `inputs`, `sandbox`.

**STDIO:**

| Field | Required | Role |
| --- | --- | --- |
| `type` | Yes (`"stdio"`) in reference table; examples sometimes omit | Transport |
| `command` | Yes | Executable |
| `args` | No | Args |
| `cwd` | No | Working directory |
| `env` | No | Env (string/number/null values) |
| `envFile` | No | Env file |
| `dev` | No | watch/debug |
| `sandboxEnabled` | No | macOS/Linux sandbox |

**HTTP / SSE:**

| Field | Required | Role |
| --- | --- | --- |
| `type` | Yes (`"http"` or `"sse"`) | Transport hint; VS Code tries Streamable HTTP then falls back to SSE for HTTP-class |
| `url` | Yes | Endpoint (also `unix://…` / `pipe://…` forms) |
| `headers` | No | HTTP headers |
| `oauth` | No | `clientId`, optional `enterpriseManaged` |

Sensitive values often use `${input:…}` placeholders backed by the `inputs` array (values may not be plaintext in the Host Config).

---

## Cross-host discovery cheat sheet

Paths VS Code documents for its own autodiscovery ([MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)) — useful as a first-party cross-check:

| Source | Path |
| --- | --- |
| Claude Desktop | Windows `%APPDATA%\Claude\claude_desktop_config.json`; macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Linux `$XDG_CONFIG_HOME/Claude/…` or `~/.config/Claude/claude_desktop_config.json` |
| Cursor global | `~/.cursor/mcp.json` |
| Cursor workspace | `<project>/.cursor/mcp.json` |
| Copilot CLI | `~/.copilot/mcp-config.json` (or `$COPILOT_HOME/…`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Windsurf / Copilot CLI are **not** destination Hosts for this ticket; listed only because the table is first-party.

---

## Transport hints for Assessment

| Signal in Host Config | Likely Transport |
| --- | --- |
| `command` present (Cursor/Claude); or `type: "stdio"` | STDIO |
| Cursor: `url` without local command | SSE or Streamable HTTP (Cursor does not always distinguish in JSON) |
| VS Code: `type: "http"` | Streamable HTTP first, SSE fallback |
| VS Code: `type: "sse"` | SSE |
| Claude Desktop file entry | STDIO only (per product docs) |

**Uncertainty:** Cursor remote entries often lack an explicit `type`; Assessment should record Transport as “remote URL (HTTP-family)” until live Surface mapping distinguishes SSE vs Streamable HTTP.

---

## Stable Target id derivation

`CONTEXT.md` **Pin** key: *stable id from normalized command+args or normalized URL, plus Host Config path when discovered locally.*

Recommended discovery-time derivation (spec-ready; exact normalize algorithm still open):

1. **Classify** each named entry:
   - **STDIO** if `command` is set (and no competing remote-only shape).
   - **URL** if `url` is set (VS Code/`Cursor` remote).
2. **STDIO fingerprint:** normalize `command` + `args` (suggested: resolve relative args against Host Config / workspace only when unambiguous; collapse redundant separators; on Windows, case-fold drive/path carefully). **Do not** include `env` / secrets in the id (env changes must not churn the Pin key; secrets belong in Findings, not ids).
3. **URL fingerprint:** normalize URL (lowercase scheme/host; strip default ports; optional trailing-slash policy — **pick one in grill/spec and stick to it**).
4. **Disambiguator:** append the **absolute Host Config path** (and optionally the entry name) when the Target was discovered from a file, so the same binary launched from Cursor global vs project is distinct Pins if desired — matching CONTEXT’s “plus Host Config path when discovered locally.”
5. **Explicit Targets** (operator-supplied, no file): omit Host Config path; id is normalize(command+args) or normalize(URL) only.
6. **Do not** use the JSON map key (server display name) alone — names collide across Hosts and files.

**Uncertainty / open for later grilling:** exact normalize (path canonicalization, `${…}` interpolation before vs after hash, whether `cwd` is part of STDIO id for VS Code). Document the chosen algorithm in the Pin ticket.

---

## What Assessment should parse vs ignore (v1)

| Include | Skip / note only |
| --- | --- |
| `command`, `args`, `env`, `envFile`, `cwd` | OAuth secrets in `auth` / `oauth` — redact in Report; interactive OAuth out of scope per map |
| `url`, `headers` | Claude Desktop remote Connectors (no local Host Config) |
| Transport `type` when present | VS Code enable/disable UI state (separate store) |
| Host Config absolute path + entry name | Team Marketplace / Cloud-only Cursor admin configs |

---

## Source index

| Claim area | Primary source |
| --- | --- |
| Cursor paths, schema, transports, interpolation | https://cursor.com/docs/mcp |
| Cursor merge / project vs global | https://cursor.com/help/customization/mcp |
| Claude Desktop macOS/Windows path + `mcpServers` STDIO shape | https://modelcontextprotocol.io/docs/develop/connect-local-servers |
| Claude remote = Connectors, not local file | https://support.anthropic.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp |
| VS Code paths (workspace/user), `servers` schema, discovery table | https://code.visualstudio.com/docs/agents/reference/mcp-configuration |
| VS Code manage / Agent Host `.mcp.json` / `~/.copilot/mcp-config.json` | https://code.visualstudio.com/docs/copilot/customization/mcp-servers |
| Linux Claude config dir (SDK) | https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/cli/claude.py |

---

## Explicit uncertainties

1. Cursor Windows path: tilde-home vs documented `%USERPROFILE%` — treat as equivalent.
2. Claude Desktop on Linux: path known from VS Code/SDK; official Desktop product is macOS/Windows.
3. VS Code absolute user `mcp.json` path: inferred from User data dir.
4. Cursor remote `url` entries: SSE vs Streamable HTTP not always labeled in JSON.
5. Whether any on-disk store exists for Claude Desktop remote connectors — not found in first-party docs.
6. Insiders/VSCodium/MSIX alternate directories — not first-party defaults for v1.
7. Exact Target/Pin normalize algorithm (interpolation, case, trailing slash, `cwd`) — deferred to Pin grilling.
