"""Enumerate tools / resources / prompts with cursor pagination."""

from __future__ import annotations

from typing import Any

from mcp_assess.models import (
    EnumeratedSurface,
    PromptInfo,
    ResourceInfo,
    ToolInfo,
)
from mcp_assess.surface.classify import classify_capability, impact_class


def _tool_schema(tool: Any) -> dict[str, Any] | None:
    schema = getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None)
    if schema is None:
        return None
    if hasattr(schema, "model_dump"):
        return schema.model_dump(by_alias=True, exclude_none=True)
    if isinstance(schema, dict):
        return schema
    return dict(schema) if schema else None


def _caps_to_dict(caps: Any) -> dict[str, Any]:
    if caps is None:
        return {}
    if hasattr(caps, "model_dump"):
        return caps.model_dump(by_alias=True, exclude_none=True)
    if isinstance(caps, dict):
        return caps
    out: dict[str, Any] = {}
    for key in ("tools", "resources", "prompts", "logging", "completions"):
        val = getattr(caps, key, None)
        if val is not None:
            out[key] = True if val else False
            if hasattr(val, "model_dump"):
                out[key] = val.model_dump(exclude_none=True)
    return out


async def _list_all(method: Any, attr: str) -> list[Any]:
    items: list[Any] = []
    cursor = None
    while True:
        page = await method(cursor=cursor)
        batch = getattr(page, attr, None) or []
        items.extend(batch)
        next_cursor = getattr(page, "next_cursor", None) or getattr(
            page, "nextCursor", None
        )
        if next_cursor is None:
            break
        cursor = next_cursor
    return items


async def enumerate_target(
    client: Any,
    target_id: str,
    *,
    extra_patterns: list[str] | None = None,
    except_names: set[str] | None = None,
) -> EnumeratedSurface:
    surface = EnumeratedSurface(target_id=target_id)
    surface.protocol_version = getattr(client, "protocol_version", None)
    info = getattr(client, "server_info", None)
    if info is not None:
        if hasattr(info, "model_dump"):
            surface.server_info = info.model_dump(exclude_none=True)
        elif isinstance(info, dict):
            surface.server_info = info
        else:
            surface.server_info = {
                "name": getattr(info, "name", None),
                "version": getattr(info, "version", None),
            }
    surface.capabilities = _caps_to_dict(getattr(client, "server_capabilities", None))

    try:
        raw_tools = await _list_all(client.list_tools, "tools")
    except Exception as e:
        surface.connect_error = f"list_tools: {e}"
        raw_tools = []

    for tool in raw_tools:
        name = getattr(tool, "name", "") or ""
        desc = getattr(tool, "description", None)
        schema = _tool_schema(tool)
        surface.tools.append(
            ToolInfo(
                name=name,
                description=desc,
                input_schema=schema,
                capability_class=classify_capability(name, desc, schema),
                impact_class=impact_class(
                    name,
                    desc,
                    schema,
                    extra_patterns=extra_patterns,
                    except_names=except_names,
                ),
            )
        )

    try:
        raw_resources = await _list_all(client.list_resources, "resources")
    except Exception:
        raw_resources = []
    for res in raw_resources:
        uri = str(getattr(res, "uri", "") or "")
        name = getattr(res, "name", None)
        desc = getattr(res, "description", None)
        mime = getattr(res, "mimeType", None) or getattr(res, "mime_type", None)
        surface.resources.append(
            ResourceInfo(
                uri=uri,
                name=name,
                description=desc,
                mime_type=mime,
                impact_class=impact_class(
                    name or uri,
                    desc,
                    None,
                    extra_patterns=extra_patterns,
                    except_names=except_names,
                ),
            )
        )

    try:
        if hasattr(client, "list_resource_templates"):
            raw_tmpl = await _list_all(
                client.list_resource_templates, "resource_templates"
            )
            for t in raw_tmpl:
                if hasattr(t, "model_dump"):
                    surface.resource_templates.append(t.model_dump(exclude_none=True))
                else:
                    surface.resource_templates.append(
                        {
                            "uriTemplate": str(
                                getattr(t, "uriTemplate", None)
                                or getattr(t, "uri_template", "")
                            ),
                            "name": getattr(t, "name", None),
                            "description": getattr(t, "description", None),
                        }
                    )
    except Exception:
        pass

    try:
        raw_prompts = await _list_all(client.list_prompts, "prompts")
    except Exception:
        raw_prompts = []
    for prompt in raw_prompts:
        name = getattr(prompt, "name", "") or ""
        desc = getattr(prompt, "description", None)
        args = getattr(prompt, "arguments", None)
        arg_list = None
        if args:
            arg_list = []
            for a in args:
                if hasattr(a, "model_dump"):
                    arg_list.append(a.model_dump(exclude_none=True))
                elif isinstance(a, dict):
                    arg_list.append(a)
                else:
                    arg_list.append(
                        {
                            "name": getattr(a, "name", None),
                            "description": getattr(a, "description", None),
                            "required": getattr(a, "required", None),
                        }
                    )
        surface.prompts.append(
            PromptInfo(
                name=name,
                description=desc,
                arguments=arg_list,
                impact_class=impact_class(
                    name,
                    desc,
                    None,
                    extra_patterns=extra_patterns,
                    except_names=except_names,
                ),
            )
        )

    surface.enumerated = True
    return surface
