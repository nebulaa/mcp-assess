"""Build Surface Map objects from Target + EnumeratedSurface."""

from __future__ import annotations

import re
from typing import Any

from mcp_assess.models import EnumeratedSurface, ImpactClass, TargetSpec, Transport

_ALLOWLIST_KEYS = re.compile(
    r"ALLOWED_TOOLS|ENABLED_TOOLS|TOOLSETS|ALLOW_ONLY_|READ_ONLY",
    re.I,
)


def _allowlist_hints(env: dict[str, str]) -> dict[str, Any]:
    hints: dict[str, Any] = {}
    for key, value in env.items():
        if _ALLOWLIST_KEYS.search(key):
            if "," in value:
                hints[key] = [v.strip() for v in value.split(",") if v.strip()]
            else:
                hints[key] = value
    return hints


def _cap_bool(capabilities: dict[str, Any], key: str) -> bool:
    val = capabilities.get(key)
    if val is True:
        return True
    if isinstance(val, dict):
        return True
    return bool(val)


def weakness_hypotheses(
    target: TargetSpec,
    surface: EnumeratedSurface,
) -> list[dict[str, Any]]:
    hyps: list[dict[str, Any]] = []
    if target.url and not target.headers and not any(
        "TOKEN" in k.upper() or "KEY" in k.upper() or "SECRET" in k.upper()
        for k in target.env
    ):
        hyps.append(
            {
                "area": "authz",
                "summary": "Remote Target has no auth headers/tokens in Host Config",
                "related_check_ids": ["CFG-MISSING-REMOTE-AUTH", "ENUM-ANON-ACCESS"],
            }
        )
    if _allowlist_hints(target.env):
        hyps.append(
            {
                "area": "authz",
                "summary": "Host Config allowlist/mode keys present — verify call-time enforcement",
                "related_check_ids": ["INVOKE-LIST-CALL-GAP", "INVOKE-AUTHZ-ENFORCE"],
            }
        )
    high = [t.name for t in surface.tools if t.impact_class == ImpactClass.HIGH.value]
    if high:
        hyps.append(
            {
                "area": "scope",
                "summary": f"{len(high)} high-impact tool(s) advertised",
                "related_check_ids": ["ENUM-OVERBROAD-SURFACE", "ENUM-EXEC-CAPABILITY"],
            }
        )
    if surface.tools or surface.prompts:
        hyps.append(
            {
                "area": "poisoning",
                "summary": "Tool/prompt text should be scored by Judge",
                "related_check_ids": ["JUDGE-TOOL-POISON", "JUDGE-PROMPT-POISON"],
            }
        )
    if any(k for k in target.env if re.search(r"TOKEN|SECRET|KEY|PASSWORD", k, re.I)):
        hyps.append(
            {
                "area": "secrets",
                "summary": "Secret-like env keys present in Host Config",
                "related_check_ids": ["CFG-SECRETS-HOST"],
            }
        )
    return hyps


def build_surface_map(
    target: TargetSpec,
    surface: EnumeratedSurface,
    *,
    surface_map_id: str,
    spawned: bool = False,
) -> dict[str, Any]:
    caps = surface.capabilities
    return {
        "surface_map_id": surface_map_id,
        "scope": "target",
        "target_id": target.target_id,
        "host": target.host,
        "host_config_path": target.host_config_path,
        "host_config_key": target.host_config_key,
        "config_wiring": {
            "transport": target.transport.value,
            "command": target.command,
            "args": list(target.args) if target.args else None,
            "url": target.url,
            "env_keys": sorted(target.env.keys()),
            "header_keys": sorted(target.headers.keys()),
            "spawned_stdio": spawned
            and target.transport == Transport.STDIO,
            "auth_present": bool(target.headers)
            or any(
                re.search(r"TOKEN|SECRET|KEY|PASSWORD|AUTH", k, re.I)
                for k in target.env
            ),
            "no_sandbox": True,
        },
        "initialize": {
            "protocol_version": surface.protocol_version,
            "server_info": surface.server_info,
            "capabilities": {
                "tools": _cap_bool(caps, "tools") or bool(surface.tools),
                "resources": _cap_bool(caps, "resources") or bool(surface.resources),
                "prompts": _cap_bool(caps, "prompts") or bool(surface.prompts),
                "logging": _cap_bool(caps, "logging"),
            },
            "session_header_observed": surface.session_header_observed,
            "connect_error": surface.connect_error,
            "enumerated": surface.enumerated,
        },
        "tools": [
            {
                "name": t.name,
                "capability_class": t.capability_class,
                "impact_class": t.impact_class,
                "schema_gist": t.to_dict().get("schema_gist", ""),
                "description_excerpt": (t.description or "")[:160],
            }
            for t in surface.tools
        ],
        "resources": [r.to_dict() for r in surface.resources],
        "resource_templates": list(surface.resource_templates),
        "prompts": [
            {
                "name": p.name,
                "description_excerpt": (p.description or "")[:200],
                "impact_class": p.impact_class,
            }
            for p in surface.prompts
        ],
        "allowlist_hints": _allowlist_hints(target.env),
        "weakness_hypotheses": weakness_hypotheses(target, surface),
    }


def build_host_cross_server_map(
    host: str,
    targets: list[TargetSpec],
    surfaces: dict[str, EnumeratedSurface],
    *,
    surface_map_id: str = "sm-host-cross-server",
) -> dict[str, Any]:
    """Host-scoped Surface Map for name collisions and toxic-flow hypotheses."""
    name_to_targets: dict[str, list[str]] = {}
    for t in targets:
        surf = surfaces.get(t.target_id)
        if not surf:
            continue
        for tool in surf.tools:
            name_to_targets.setdefault(tool.name, []).append(t.target_id)

    collisions = [
        {"tool_name": name, "target_ids": ids}
        for name, ids in sorted(name_to_targets.items())
        if len(set(ids)) > 1
    ]

    toxic: list[dict[str, Any]] = []
    sources: list[tuple[str, str]] = []
    sinks: list[tuple[str, str]] = []
    for t in targets:
        surf = surfaces.get(t.target_id)
        if not surf:
            continue
        for tool in surf.tools:
            if tool.capability_class == "read":
                sources.append((t.target_id, tool.name))
            if tool.capability_class in {"egress", "exec"}:
                sinks.append((t.target_id, tool.name))
    for src_tid, src_tool in sources:
        for sink_tid, sink_tool in sinks:
            if src_tid != sink_tid:
                toxic.append(
                    {
                        "source_target_id": src_tid,
                        "source_tool": src_tool,
                        "sink_target_id": sink_tid,
                        "sink_tool": sink_tool,
                    }
                )
                if len(toxic) >= 20:
                    break
        if len(toxic) >= 20:
            break

    return {
        "surface_map_id": surface_map_id,
        "scope": "host",
        "host": host,
        "target_ids": [t.target_id for t in targets],
        "cross_server": {
            "name_collisions": collisions,
            "toxic_flow_hypotheses": toxic,
        },
        "weakness_hypotheses": [
            {
                "area": "shadowing",
                "summary": f"{len(collisions)} tool name collision(s) across Targets",
                "related_check_ids": ["ENUM-TOOL-SHADOW"],
            }
        ]
        if collisions
        else [],
    }
