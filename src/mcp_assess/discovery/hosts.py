"""Host Config discovery for Cursor, Claude Desktop, and VS Code."""

from __future__ import annotations

import json
import os
import platform
import re
from pathlib import Path
from typing import Any, Iterable

from mcp_assess.discovery.target_id import (
    normalize_path,
    target_id_for_stdio,
    target_id_for_url,
)
from mcp_assess.models import TargetSpec, Transport

_INTERP = re.compile(
    r"\$\{(?:env:([^}]+)|userHome|workspaceFolder|workspaceFolderBasename|pathSeparator|/)}"
)


def _expand_interp(value: str, *, workspace: Path | None = None) -> str:
    home = str(Path.home())
    ws = str(workspace) if workspace else home
    ws_base = Path(ws).name

    def repl(m: re.Match[str]) -> str:
        env_name = m.group(1)
        if env_name is not None:
            return os.environ.get(env_name, "")
        full = m.group(0)
        if "userHome" in full:
            return home
        if "workspaceFolderBasename" in full:
            return ws_base
        if "workspaceFolder" in full:
            return ws
        if "pathSeparator" in full or full.endswith("${/}"):
            return os.sep
        return ""

    return _INTERP.sub(repl, value)


def _expand_mapping(
    obj: Any, *, workspace: Path | None = None
) -> Any:
    if isinstance(obj, str):
        return _expand_interp(obj, workspace=workspace)
    if isinstance(obj, list):
        return [_expand_mapping(x, workspace=workspace) for x in obj]
    if isinstance(obj, dict):
        return {k: _expand_mapping(v, workspace=workspace) for k, v in obj.items()}
    return obj


def _xdg_config() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def cursor_paths(*, project_root: Path | None = None) -> list[tuple[str, Path]]:
    paths: list[tuple[str, Path]] = [
        ("cursor", Path.home() / ".cursor" / "mcp.json"),
    ]
    root = project_root or Path.cwd()
    paths.append(("cursor", root / ".cursor" / "mcp.json"))
    return paths


def claude_desktop_paths() -> list[tuple[str, Path]]:
    system = platform.system()
    paths: list[Path] = []
    if system == "Darwin":
        paths.append(
            Path.home()
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    # Linux / secondary
    paths.append(_xdg_config() / "Claude" / "claude_desktop_config.json")
    return [("claude_desktop", p) for p in paths]


def vscode_paths(*, project_root: Path | None = None) -> list[tuple[str, Path]]:
    system = platform.system()
    user: list[Path] = []
    if system == "Darwin":
        user.append(
            Path.home()
            / "Library"
            / "Application Support"
            / "Code"
            / "User"
            / "mcp.json"
        )
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            user.append(Path(appdata) / "Code" / "User" / "mcp.json")
    else:
        user.append(_xdg_config() / "Code" / "User" / "mcp.json")
    root = project_root or Path.cwd()
    paths = [("vscode", p) for p in user]
    paths.append(("vscode", root / ".vscode" / "mcp.json"))
    return paths


def discover_host_config_paths(
    *,
    all_hosts: bool = False,
    config_paths: list[Path] | None = None,
    project_root: Path | None = None,
) -> list[tuple[str, Path]]:
    """Return (host_name, path) pairs that exist (or explicit --config paths)."""
    if config_paths:
        return [
            ("explicit", Path(normalize_path(str(p)))) for p in config_paths
        ]

    candidates = cursor_paths(project_root=project_root)
    if all_hosts:
        candidates = (
            cursor_paths(project_root=project_root)
            + claude_desktop_paths()
            + vscode_paths(project_root=project_root)
        )

    seen: set[str] = set()
    existing: list[tuple[str, Path]] = []
    for host, path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if path.is_file():
            existing.append((host, path))
    return existing


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {}
    return data


def _server_map(data: dict[str, Any]) -> dict[str, Any]:
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        return data["mcpServers"]
    if "servers" in data and isinstance(data["servers"], dict):
        return data["servers"]
    return {}


def _headers_from_entry(entry: dict[str, Any]) -> dict[str, str]:
    raw = entry.get("headers") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v is not None}


def _env_from_entry(entry: dict[str, Any]) -> dict[str, str]:
    raw = entry.get("env") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if v is None:
            continue
        out[str(k)] = str(v)
    return out


def _transport_for_entry(entry: dict[str, Any]) -> Transport:
    type_hint = str(entry.get("type") or "").lower()
    if type_hint == "sse":
        return Transport.SSE
    if type_hint in {"http", "streamable_http", "streamable-http"}:
        return Transport.STREAMABLE_HTTP
    if type_hint == "stdio" or entry.get("command"):
        return Transport.STDIO
    if entry.get("url"):
        return Transport.REMOTE_HTTP
    return Transport.STDIO


def entry_to_target(
    name: str,
    entry: dict[str, Any],
    *,
    host: str,
    host_config_path: Path,
    workspace: Path | None = None,
) -> TargetSpec | None:
    if not isinstance(entry, dict):
        return None
    expanded = _expand_mapping(entry, workspace=workspace)
    assert isinstance(expanded, dict)
    transport = _transport_for_entry(expanded)
    path_str = normalize_path(str(host_config_path))

    if transport == Transport.STDIO or expanded.get("command"):
        command = expanded.get("command")
        if not command:
            return None
        args = [str(a) for a in (expanded.get("args") or [])]
        env = _env_from_entry(expanded)
        cwd = expanded.get("cwd")
        tid = target_id_for_stdio(str(command), args, host_config_path=path_str)
        return TargetSpec(
            target_id=tid,
            name=name,
            transport=Transport.STDIO,
            host=host,
            host_config_path=path_str,
            host_config_key=name,
            command=str(command),
            args=args,
            cwd=str(cwd) if cwd else None,
            env=env,
            spawn=True,
        )

    url = expanded.get("url")
    if not url:
        return None
    headers = _headers_from_entry(expanded)
    tid = target_id_for_url(str(url), host_config_path=path_str)
    return TargetSpec(
        target_id=tid,
        name=name,
        transport=transport,
        host=host,
        host_config_path=path_str,
        host_config_key=name,
        url=str(url),
        headers=headers,
        env=_env_from_entry(expanded),
        spawn=False,
    )


def parse_host_config(
    path: Path,
    *,
    host: str,
    workspace: Path | None = None,
) -> tuple[dict[str, TargetSpec], list[str]]:
    """Parse one Host Config file → name→TargetSpec (later files overwrite same name when merging)."""
    notes: list[str] = []
    try:
        data = _load_json(path)
    except (OSError, json.JSONDecodeError) as e:
        notes.append(f"Failed to read {path}: {e}")
        return {}, notes

    servers = _server_map(data)
    targets: dict[str, TargetSpec] = {}
    for name, entry in servers.items():
        spec = entry_to_target(
            name, entry, host=host, host_config_path=path, workspace=workspace
        )
        if spec:
            targets[name] = spec

    if host == "claude_desktop":
        notes.append(
            "Claude Desktop remote Connectors are not in the local Host Config file "
            "and are undiscoverable in v1."
        )
    return targets, notes


def merge_cursor_targets(
    global_targets: dict[str, TargetSpec],
    project_targets: dict[str, TargetSpec],
) -> dict[str, TargetSpec]:
    """Project wins on name clash."""
    merged = dict(global_targets)
    merged.update(project_targets)
    return merged


def discover_targets(
    *,
    all_hosts: bool = False,
    config_paths: list[Path] | None = None,
    project_root: Path | None = None,
    name_filter: list[str] | None = None,
) -> tuple[list[TargetSpec], list[dict[str, Any]], list[str]]:
    """Discover Targets from Host Configs.

    Returns (targets, hosts_meta, notes).
    """
    root = project_root or Path.cwd()
    path_pairs = discover_host_config_paths(
        all_hosts=all_hosts, config_paths=config_paths, project_root=root
    )
    notes: list[str] = []
    hosts_meta: list[dict[str, Any]] = []
    # Cursor merge: collect by host then merge names
    by_host: dict[str, list[tuple[Path, dict[str, TargetSpec]]]] = {}

    for host, path in path_pairs:
        targets, file_notes = parse_host_config(path, host=host, workspace=root)
        notes.extend(file_notes)
        by_host.setdefault(host, []).append((path, targets))
        hosts_meta.append(
            {
                "host": host,
                "host_config_paths": [normalize_path(str(path))],
                "target_count": len(targets),
            }
        )

    result: list[TargetSpec] = []
    for host, files in by_host.items():
        if host == "cursor" and len(files) > 1:
            # Merge: later project file wins — order from cursor_paths is global then project
            merged: dict[str, TargetSpec] = {}
            for _path, targets in files:
                merged.update(targets)
            result.extend(merged.values())
        else:
            for _path, targets in files:
                result.extend(targets.values())

    # Dedupe by target_id (keep first)
    seen_ids: set[str] = set()
    unique: list[TargetSpec] = []
    for t in result:
        if t.target_id in seen_ids:
            continue
        seen_ids.add(t.target_id)
        unique.append(t)

    if name_filter:
        filters = set(name_filter)
        unique = [
            t
            for t in unique
            if (t.name and t.name in filters)
            or t.target_id in filters
            or (t.url and t.url in filters)
        ]

    return unique, hosts_meta, notes


def explicit_url_target(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    bearer: str | None = None,
    transport: Transport = Transport.STREAMABLE_HTTP,
) -> TargetSpec:
    hdrs = dict(headers or {})
    if bearer:
        hdrs.setdefault("Authorization", f"Bearer {bearer}")
    return TargetSpec(
        target_id=target_id_for_url(url),
        name=None,
        transport=transport,
        url=url,
        headers=hdrs,
        spawn=False,
    )


def iter_existing(paths: Iterable[Path]) -> list[Path]:
    return [p for p in paths if p.is_file()]
