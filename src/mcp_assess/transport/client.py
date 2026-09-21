"""MCP transport client wrappers for STDIO / SSE / Streamable HTTP."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp_assess.models import TargetSpec, Transport


@asynccontextmanager
async def open_client(
    target: TargetSpec,
    *,
    override_headers: dict[str, str] | None = None,
    strip_auth: bool = False,
) -> AsyncIterator[Any]:
    """Yield a connected high-level MCP Client for the Target.

    `strip_auth` connects without Host Config / override credentials (anon probe).
    """
    from mcp import Client, StdioServerParameters

    headers = {} if strip_auth else dict(target.headers)
    if override_headers and not strip_auth:
        headers.update(override_headers)

    if target.transport == Transport.STDIO or (
        target.command and not target.url
    ):
        if not target.command:
            raise ValueError(f"STDIO Target missing command: {target.target_id}")
        params = StdioServerParameters(
            command=target.command,
            args=list(target.args),
            env=dict(target.env) if target.env else None,
            cwd=target.cwd,
        )
        async with Client(params) as client:
            yield client
        return

    if not target.url:
        raise ValueError(f"URL Target missing url: {target.target_id}")

    url = target.url
    transport = target.transport

    if transport == Transport.SSE:
        from mcp.client.sse import sse_client

        async with Client(sse_client(url, headers=headers or None)) as client:
            yield client
        return

    # Streamable HTTP or remote_http (try streamable first)
    if headers:
        import httpx2
        from mcp.client.streamable_http import streamable_http_client

        async with httpx2.AsyncClient(
            headers=headers,
            timeout=httpx2.Timeout(30.0, read=300.0),
        ) as http_client:
            transport_cm = streamable_http_client(url, http_client=http_client)
            async with Client(transport_cm) as client:
                yield client
        return

    async with Client(url) as client:
        yield client


async def try_open_with_fallback(
    target: TargetSpec,
    *,
    strip_auth: bool = False,
) -> AsyncIterator[tuple[Any, Transport]]:
    """For REMOTE_HTTP, try Streamable HTTP then SSE."""
    from mcp_assess.models import Transport as T

    if target.transport in {T.STDIO, T.SSE, T.STREAMABLE_HTTP}:
        async with open_client(target, strip_auth=strip_auth) as client:
            yield client, target.transport
        return

    # remote_http: try streamable, then sse
    streamable = TargetSpec(
        target_id=target.target_id,
        name=target.name,
        transport=T.STREAMABLE_HTTP,
        host=target.host,
        host_config_path=target.host_config_path,
        host_config_key=target.host_config_key,
        url=target.url,
        headers=dict(target.headers),
        env=dict(target.env),
        spawn=False,
    )
    try:
        async with open_client(streamable, strip_auth=strip_auth) as client:
            yield client, T.STREAMABLE_HTTP
            return
    except Exception:
        pass

    sse = TargetSpec(
        target_id=target.target_id,
        name=target.name,
        transport=T.SSE,
        host=target.host,
        host_config_path=target.host_config_path,
        host_config_key=target.host_config_key,
        url=target.url,
        headers=dict(target.headers),
        env=dict(target.env),
        spawn=False,
    )
    async with open_client(sse, strip_auth=strip_auth) as client:
        yield client, T.SSE
