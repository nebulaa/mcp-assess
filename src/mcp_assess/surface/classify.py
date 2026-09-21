"""High-impact / capability classifiers (high-impact-v1)."""

from __future__ import annotations

import re
from typing import Any

from mcp_assess.models import CapabilityClass, ImpactClass

CLASSIFIER_ID = "high-impact-v1"

# Verb / token families from Invoke policy grill
_HIGH_IMPACT_TOKENS = [
    r"exec",
    r"shell",
    r"bash",
    r"powershell",
    r"\bcmd\b",
    r"subprocess",
    r"\beval\b",
    r"\bsystem\b",
    r"run_command",
    r"kubectl",
    r"exec_in_pod",
    r"node_management",
    r"delete",
    r"destroy",
    r"\bdrop\b",
    r"purge",
    r"truncate",
    r"remove",
    r"\bkill\b",
    r"write",
    r"\bput\b",
    r"patch",
    r"update",
    r"create",
    r"mkdir",
    r"upload",
    r"\bsend\b",
    r"email",
    r"slack",
    r"webhook",
    r"notify",
    r"post_url",
    r"fetch_url",
    r"http_request",
    r"payment",
    r"transfer",
    r"invoice_charge",
    r"\badmin\b",
    r"\biam\b",
    r"role_bind",
    r"\bgrant\b",
    r"revoke",
    r"set_policy",
]

_LOW_IMPACT_HINTS = [
    r"^get_",
    r"^list_",
    r"^read_",
    r"^search_",
    r"^find_",
    r"^describe_",
    r"^show_",
    r"^status",
    r"^echo",
    r"^ping",
    r"^health",
]

_CAPABILITY_RULES: list[tuple[str, re.Pattern[str]]] = [
    (CapabilityClass.EXEC.value, re.compile(r"exec|shell|bash|subprocess|eval|run_command|kubectl", re.I)),
    (CapabilityClass.EGRESS.value, re.compile(r"http_request|fetch_url|post_url|webhook|email|slack|send|notify", re.I)),
    (CapabilityClass.ADMIN.value, re.compile(r"admin|iam|role_bind|grant|revoke|set_policy", re.I)),
    (CapabilityClass.MUTATE.value, re.compile(r"write|create|update|delete|destroy|put|patch|mkdir|upload|remove|purge", re.I)),
    (CapabilityClass.READ.value, re.compile(r"get|list|read|search|find|describe|show|status|ping|health|echo", re.I)),
]


def _flatten_text(name: str, description: str | None, schema: dict[str, Any] | None) -> str:
    parts = [name or "", description or ""]
    if schema:
        parts.append(_json_words(schema))
    return " ".join(parts)


def _json_words(obj: Any) -> str:
    if isinstance(obj, dict):
        return " ".join(f"{k} {_json_words(v)}" for k, v in obj.items())
    if isinstance(obj, list):
        return " ".join(_json_words(x) for x in obj)
    return str(obj)


def classify_capability(
    name: str,
    description: str | None = None,
    schema: dict[str, Any] | None = None,
) -> str:
    text = _flatten_text(name, description, schema)
    for cap, pattern in _CAPABILITY_RULES:
        if pattern.search(text):
            return cap
    return CapabilityClass.OTHER.value


def is_high_impact(
    name: str,
    description: str | None = None,
    schema: dict[str, Any] | None = None,
    *,
    extra_patterns: list[str] | None = None,
    except_names: set[str] | None = None,
) -> bool:
    if except_names and name in except_names:
        return False
    text = _flatten_text(name, description, schema)
    patterns = list(_HIGH_IMPACT_TOKENS)
    if extra_patterns:
        patterns.extend(extra_patterns)
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            # dry-run / validate-only carve-out for write-ish names
            if re.search(r"dry[_-]?run|validate[_-]?only|read[_-]?only", text, re.I):
                continue
            return True
    return False


def impact_class(
    name: str,
    description: str | None = None,
    schema: dict[str, Any] | None = None,
    *,
    extra_patterns: list[str] | None = None,
    except_names: set[str] | None = None,
) -> str:
    if is_high_impact(
        name,
        description,
        schema,
        extra_patterns=extra_patterns,
        except_names=except_names,
    ):
        return ImpactClass.HIGH.value
    return ImpactClass.LOW.value


def looks_low_impact_name(name: str) -> bool:
    return any(re.search(p, name, re.I) for p in _LOW_IMPACT_HINTS)
