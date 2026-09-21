# Python MCP SDK client transports (STDIO / SSE / Streamable HTTP)

**Question:** With the official MCP Python SDK (current stable), what does a client need to speak STDIO, SSE, and Streamable HTTP for Enumerate and Invoke?

**Pinned package:** [`mcp` 2.2.0 on PyPI](https://pypi.org/project/mcp/) (2026-04 era; pulls `httpx2`, `mcp-types==2.2.0`, `anyio`, etc.). Docs: [Client transports](https://py.sdk.modelcontextprotocol.io/client/transports/), [The Client](https://py.sdk.modelcontextprotocol.io/client/). Source: [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk).

Vocabulary follows repo `CONTEXT.md` (Target, Transport, Enumerate, Invoke).

---

## Package and high-level API

| Need | Package / import |
|------|------------------|
| Install | `mcp` (PyPI); HTTP stack is **`httpx2`**, not classic `httpx` |
| High-level client | `from mcp import Client` — one object for all Transports after connect |
| STDIO params | `from mcp import StdioServerParameters` (also `mcp.client.stdio`) |
| STDIO transport | `stdio_client` from `mcp` / `mcp.client.stdio` |
| Streamable HTTP transport | `from mcp.client.streamable_http import streamable_http_client` |
| Legacy SSE transport | `from mcp.client.sse import sse_client` |
| Low-level session | `ClientSession` (`mcp.client.session`) — escape hatch under `client.session` |
| Types | Prefer `mcp.types` / `mcp_types` (v2 snake_case attrs on results: `next_cursor`, `structured_content`, `is_error`) |

`Client` resolves its single positional argument by type ([docs](https://py.sdk.modelcontextprotocol.io/client/transports/)):

- `str` URL → Streamable HTTP via `streamable_http_client(url)`
- `StdioServerParameters` → STDIO via `stdio_client(params)`
- Any other async context manager yielding `(read, write)` → entered as a Transport (covers explicit `streamable_http_client(...)`, `sse_client(...)`, custom)
- In-process `MCPServer` / `Server` → memory (tests only; not a Target Transport for Assessment)

Construction only picks the Transport; **`async with` connects and completes the handshake**. There is no separate `connect()` / `initialize()` call on the high-level `Client` ([Client docs](https://py.sdk.modelcontextprotocol.io/client/); `__aenter__` in [`src/mcp/client/client.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/client.py)).

Default handshake mode is **`auto`**: negotiate modern protocol or fall back to classic `initialize`. Inside the block, `client.server_info`, `client.server_capabilities`, `client.protocol_version`, and `client.instructions` are already populated when the Target provides them.

---

## Per-Transport connect recipe

### Streamable HTTP (production / URL Targets)

```python
from mcp import Client

async with Client("http://localhost:8000/mcp") as client:
    ...
```

Auth / headers / timeouts / proxy / mTLS: **do not** pass `headers=` to `streamable_http_client` (removed; raises `TypeError`). Build an `httpx2.AsyncClient` and pass it:

```python
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

async with httpx2.AsyncClient(
    headers={"Authorization": "Bearer ..."},
    timeout=httpx2.Timeout(30.0, read=300.0),
) as http_client:
    transport = streamable_http_client("http://localhost:8000/mcp", http_client=http_client)
    async with Client(transport) as client:
        ...
```

Source signature ([`streamable_http.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/streamable_http.py)): `streamable_http_client(url, *, http_client=None, terminate_on_close=True)`. If `http_client` is omitted, the SDK creates one via `create_mcp_http_client()` (30s connect/write/pool, 300s read) and owns its lifecycle; if you pass one, **you** enter/exit it.

**Redirects:** only same-origin `307`/`308` (and `http`→`https` on same host). Cross-origin redirects fail with an error naming the location — configure the final URL ([docs](https://py.sdk.modelcontextprotocol.io/client/transports/#redirects)). Caller `follow_redirects` on httpx2 is ignored for MCP requests.

**Session teardown:** default `terminate_on_close=True` sends DELETE for the MCP session id on exit.

TLS: `httpx2` uses the OS trust store (`truststore`); minimal containers may need `SSL_CERT_FILE` / `SSL_CERT_DIR` or `verify=`.

### STDIO (local spawn Targets)

```python
from mcp import Client, StdioServerParameters

server = StdioServerParameters(
    command="uv",
    args=["run", "server.py"],
    env={"BOOKSHOP_API_KEY": "secret"},  # merged over allow-list
    cwd=None,
)
async with Client(server) as client:
    ...
```

Spawn/shutdown are owned by the context manager (close stdin → wait → kill tree). Optional stderr redirect: `Client(stdio_client(server, errlog=log_file))`.

**Environment pass-through** ([`stdio.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/stdio.py)):

- Child does **not** inherit the full parent environment.
- Baseline = `get_default_environment()` allow-list:
  - POSIX: `HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER`
  - Windows: `APPDATA`, `HOMEDRIVE`, `HOMEPATH`, `LOCALAPPDATA`, `PATH`, `PATHEXT`, `PROCESSOR_ARCHITECTURE`, `SYSTEMDRIVE`, `SYSTEMROOT`, `TEMP`, `USERNAME`, `USERPROFILE`
- `StdioServerParameters.env` is **merged on top**: `get_default_environment() | (server.env or {})`.
- Host Config `env` maps (and Assessment-supplied secrets) must be copied into `env=` explicitly or the Target will not see them.

### SSE (legacy HTTP Targets)

```python
from mcp import Client
from mcp.client.sse import sse_client

async with Client(sse_client("http://localhost:8000/sse", headers={...}, auth=...)) as client:
    ...
```

Docs mark SSE as superseded by Streamable HTTP; still supported for Targets that only speak SSE ([transports](https://py.sdk.modelcontextprotocol.io/client/transports/#sse)).

API differs from Streamable HTTP ([`sse.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/sse.py)): `sse_client(url, headers=None, timeout=5.0, sse_read_timeout=300.0, httpx_client_factory=..., auth=None, on_session_created=...)`. Headers/auth still land directly on the factory-built client (or via `httpx_client_factory`). Same within-origin redirect rule as Streamable HTTP.

Wire shape: GET SSE for events (`endpoint` + `message`); client POSTs JSON-RPC to the advertised message endpoint.

---

## Enumerate and Invoke (same verbs on every Transport)

After `async with Client(...)`, protocol verbs are identical regardless of Transport ([Client docs](https://py.sdk.modelcontextprotocol.io/client/)):

| Assessment action | Client method | Notes |
|-------------------|---------------|--------|
| Handshake | *(automatic on enter)* | Properties: `server_capabilities`, `protocol_version`, … |
| Enumerate tools | `await client.list_tools(cursor=...)` | → `ListToolsResult.tools` |
| Enumerate resources | `await client.list_resources(cursor=...)` | plus `list_resource_templates` |
| Enumerate prompts | `await client.list_prompts(cursor=...)` | |
| Read resource | `await client.read_resource(uri)` | |
| Get prompt | `await client.get_prompt(name, arguments)` | arguments are `str → str` |
| **Invoke** | `await client.call_tool(name, arguments)` | → `CallToolResult` |

**Invoke result shape (v2):** `content` (model-facing blocks), `structured_content` (JSON for code), `is_error` (bool). A tool failure / unknown tool is typically a **result with `is_error=True`**, not a raised exception. JSON-RPC / transport failures raise `MCPError`.

**Low-level path** (v1-style still present): `async with stdio_client` / `streamable_http_client` / `sse_client` as streams → `async with ClientSession(read, write)` → **`await session.initialize()`** → same list/call methods. Prefer `Client` for mcp-assess unless a Check needs session callbacks (sampling, elicitation, logging).

---

## Pagination

MCP list ops use opaque cursors ([spec pagination](https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/pagination); [SDK pagination](https://py.sdk.modelcontextprotocol.io/advanced/pagination/)).

Covered methods: `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`.

Client loop (must appear in Surface Map enumeration):

```python
async def list_all_tools(client: Client) -> list:
    tools, cursor = [], None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        if page.next_cursor is None:
            return tools
        cursor = page.next_cursor
```

Rules for the spec: treat cursors as opaque; do not persist across sessions; missing/`None` `next_cursor` means done; page size is server-owned. A single-page Target still works (one iteration).

Low-level `ClientSession.list_tools(params=PaginatedRequestParams(cursor=...))` is equivalent; high-level `Client` wraps that.

---

## Auth header / env pass-through (mcp-assess mapping)

| Transport | How Assessment passes Host Config / CLI auth |
|-----------|-----------------------------------------------|
| STDIO | Map Host Config `env` → `StdioServerParameters.env` (merge over allow-list). No HTTP headers. |
| Streamable HTTP | Map bearer / header flags → `httpx2.AsyncClient(headers=...)` → `streamable_http_client(..., http_client=...)`. Optional `auth=` on that client (incl. SDK `OAuthClientProvider`, **out of product scope** for v1). |
| SSE | Map headers → `sse_client(..., headers=..., auth=...)` (or custom `httpx_client_factory`). |

Destination standing preference (map Out of scope): **no interactive OAuth / device-code** in mcp-assess v1 — Host Config + bearer/header flags only. The SDK *can* do OAuth via httpx2 `auth=`; the Assessment product must not require that path.

---

## Gaps and limitations the mcp-assess spec must call out

1. **SSE is first-class for Assessment Targets but legacy in the SDK.** Still import `mcp.client.sse.sse_client`; do not design new Targets around it. Auth knobs differ from Streamable HTTP (`headers=` vs BYO `httpx2.AsyncClient`).
2. **Streamable HTTP has no `headers=` on the transport helper** (breaking vs older snippets / v1 docs). Spec and implementers must document the httpx2 client pattern.
3. **STDIO env allow-list** — spawning “as Host Config” means copying declared `env` into `StdioServerParameters.env`; full `os.environ` inheritance is *not* what the SDK does. Aligns with destination “spawn as-is” for command/args, but env semantics are SDK-defined.
4. **No sandbox** — SDK spawn is plain subprocess / process group; Report must note Assessment does not add OS sandboxing (map Out of scope).
5. **Redirect / URL exactness** — cross-origin or HTTPS→HTTP redirects fail; Surface Map / Findings may need a “misconfigured URL / proxy” class when connect fails this way.
6. **Pagination required for complete Enumerate** — single `list_*` without cursor follow can under-report Surface Map on paged Targets.
7. **`call_tool` error model** — Checks that treat exceptions as Invoke failure will miss `is_error=True` results; AuthZ list-vs-call Checks must inspect result + HTTP/transport status separately.
8. **Transport divergence Checks** — same high-level verbs across Transports make alternate-path Enumerate/Invoke feasible (Unsafe mode); SSE vs Streamable HTTP auth plumbing differs, so “same headers on both” is an Assessment concern, not automatic.
9. **OAuth in SDK ≠ OAuth in product** — document that interactive OAuth remains manual / out of scope even though `OAuthClientProvider` exists.
10. **Version coupling** — pin `mcp` (and thus `mcp-types`, `httpx2`); v1 `ClientSession` + `httpx` examples still circulate and must not be copied blindly into the spec.
11. **Protocol version auto-negotiation** — default `auto` mode is appropriate; pinning a single protocol version is optional advanced config, not required for v1 Enumerate/Invoke.
12. **In-memory `Client(mcp)`** — useful for unit tests of Assessment code paths; not a live Target Transport.

---

## Minimal Enumerate + Invoke sketch (all three)

```python
import anyio
import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client

async def enumerate_and_invoke(client: Client) -> None:
    caps = client.server_capabilities
    tools = []
    cursor = None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    # similarly: list_resources, list_resource_templates, list_prompts
    if tools:
        result = await client.call_tool(tools[0].name, {})
        _ = result.is_error, result.content, result.structured_content

async def via_stdio() -> None:
    params = StdioServerParameters(command="uv", args=["run", "server.py"], env={"KEY": "v"})
    async with Client(params) as client:
        await enumerate_and_invoke(client)

async def via_streamable(url: str, bearer: str | None) -> None:
    if bearer:
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {bearer}"}) as http:
            async with Client(streamable_http_client(url, http_client=http)) as client:
                await enumerate_and_invoke(client)
    else:
        async with Client(url) as client:
            await enumerate_and_invoke(client)

async def via_sse(url: str, headers: dict | None) -> None:
    async with Client(sse_client(url, headers=headers)) as client:
        await enumerate_and_invoke(client)
```

---

## Sources

- [Client transports (SDK docs)](https://py.sdk.modelcontextprotocol.io/client/transports/)
- [The Client (SDK docs)](https://py.sdk.modelcontextprotocol.io/client/)
- [Pagination (SDK docs)](https://py.sdk.modelcontextprotocol.io/advanced/pagination/)
- [MCP pagination (spec)](https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/pagination)
- [PyPI `mcp`](https://pypi.org/project/mcp/) — current stable **2.2.0** at research time
- Source: [`stdio.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/stdio.py), [`streamable_http.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/streamable_http.py), [`sse.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/sse.py), [`client.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/client.py), [`_httpx_utils.py`](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/shared/_httpx_utils.py)
- Legacy reference (v1 `ClientSession` + `headers` on streamable patterns): [Writing Clients (v1)](https://py.sdk.modelcontextprotocol.io/v1/client/)
