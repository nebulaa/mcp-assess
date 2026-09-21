"""Secret redaction helpers for Reports and evidence."""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Patterns that look like secrets in Host Config values
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("pem_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("bearer_header", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-+/=]{8,}")),
    ("generic_api_key", re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*\S{8,}")),
    ("long_token", re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_\-+/=]{32,}(?![A-Za-z0-9])")),
]

SECRET_ENV_KEY = re.compile(
    r"(?i)(token|secret|password|passwd|api[_-]?key|auth|credential|private[_-]?key|bearer)"
)


def fingerprint(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    last4 = value[-4:] if len(value) >= 4 else value
    return f"sha256:{digest}/…{last4}"


def looks_secret_key(key: str) -> bool:
    return bool(SECRET_ENV_KEY.search(key))


def looks_secret_value(value: str) -> tuple[bool, str | None]:
    if not value or len(value) < 8:
        return False, None
    for name, pat in SECRET_PATTERNS:
        if pat.search(value):
            return True, name
    return False, None


def redact_value(value: str, *, show_secrets: bool = False) -> str:
    if show_secrets:
        return value
    return fingerprint(value)


def redact_mapping(
    data: dict[str, Any],
    *,
    show_secrets: bool = False,
    keys_always: bool = True,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, dict):
            out[k] = redact_mapping(v, show_secrets=show_secrets, keys_always=keys_always)
        elif isinstance(v, list):
            out[k] = [
                redact_mapping(x, show_secrets=show_secrets)
                if isinstance(x, dict)
                else (
                    redact_value(x, show_secrets=show_secrets)
                    if isinstance(x, str)
                    and (looks_secret_key(k) or looks_secret_value(x)[0])
                    else x
                )
                for x in v
            ]
        elif isinstance(v, str):
            if keys_always and looks_secret_key(str(k)):
                out[k] = redact_value(v, show_secrets=show_secrets)
            else:
                is_secret, _ = looks_secret_value(v)
                out[k] = redact_value(v, show_secrets=show_secrets) if is_secret else v
        else:
            out[k] = v
    return out


def redact_command_line(argv: list[str], *, show_secrets: bool = False) -> str:
    if show_secrets:
        return " ".join(argv)
    redacted: list[str] = []
    skip_next = False
    secret_flags = {"--bearer", "--header", "--judge-cmd"}
    for i, arg in enumerate(argv):
        if skip_next:
            redacted.append("***")
            skip_next = False
            continue
        if arg in secret_flags:
            redacted.append(arg)
            skip_next = True
            continue
        if arg.startswith("--bearer=") or arg.startswith("--header="):
            key, _, _val = arg.partition("=")
            redacted.append(f"{key}=***")
            continue
        is_secret, _ = looks_secret_value(arg)
        redacted.append(redact_value(arg) if is_secret else arg)
    return " ".join(redacted)
