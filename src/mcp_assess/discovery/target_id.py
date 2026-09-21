"""Stable Target id normalization."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse


def normalize_path(path: str) -> str:
    try:
        return str(Path(path).expanduser().resolve())
    except OSError:
        return str(Path(path).expanduser())


def normalize_url(url: str) -> str:
    """Lowercase scheme/host; strip default ports and ephemeral query; drop trailing slash on path."""
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is not None:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        else:
            netloc = f"{host}:{port}"
    else:
        netloc = host
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    # Drop query (ephemeral tokens) and fragment from Target id
    return urlunparse((scheme, netloc, path, "", "", ""))


def normalize_stdio(command: str, args: list[str] | None = None) -> str:
    parts = [command.strip()]
    for a in args or []:
        parts.append(str(a).strip())
    # Collapse internal whitespace in each token; keep args as distinct
    return " ".join(re.sub(r"\s+", " ", p) for p in parts if p)


def target_id_for_stdio(
    command: str,
    args: list[str] | None = None,
    *,
    host_config_path: str | None = None,
) -> str:
    base = f"stdio:{normalize_stdio(command, args)}"
    if host_config_path:
        return f"{base}|host_config:{normalize_path(host_config_path)}"
    return base


def target_id_for_url(
    url: str,
    *,
    host_config_path: str | None = None,
) -> str:
    base = f"url:{normalize_url(url)}"
    if host_config_path:
        return f"{base}|host_config:{normalize_path(host_config_path)}"
    return base


def pin_key(target_id: str, host_config_path: str | None = None) -> str:
    """Pin key = target_id|host_config:<abs_or_empty>.

    If target_id already embeds host_config, use it as the pin key.
    """
    if "|host_config:" in target_id:
        return target_id
    path = normalize_path(host_config_path) if host_config_path else ""
    return f"{target_id}|host_config:{path}"
