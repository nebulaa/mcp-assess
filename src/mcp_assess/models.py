"""Shared data models for Assessment, Targets, Findings, and Reports."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Transport(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"
    REMOTE_HTTP = "remote_http"  # URL present; SSE vs Streamable unknown until live


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    FINDING = "finding"
    INFORMATIONAL = "informational"
    MANUAL_REQUIRED = "manual_required"
    SKIPPED = "skipped"


class AssessmentMode(str, Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"


class ImpactClass(str, Enum):
    LOW = "low"
    HIGH = "high-impact"


class CapabilityClass(str, Enum):
    READ = "read"
    MUTATE = "mutate"
    EXEC = "exec"
    EGRESS = "egress"
    ADMIN = "admin"
    OTHER = "other"


@dataclass
class OwaspCitation:
    id: str
    title: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class AtlasCitation:
    id: str
    title: str | None = None
    url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id}
        if self.title:
            d["title"] = self.title
        if self.url:
            d["url"] = self.url
        return d


@dataclass
class Remediation:
    summary: str
    urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"summary": self.summary, "urls": list(self.urls)}


@dataclass
class Finding:
    id: str
    title: str
    check_id: str
    check_name: str
    owasp: OwaspCitation
    severity: Severity
    status: FindingStatus
    depth: str
    assessment_mode: str
    evidence: dict[str, Any] = field(default_factory=dict)
    atlas: list[AtlasCitation] = field(default_factory=list)
    target_id: str | None = None
    host_config_path: str | None = None
    redacted: bool = True
    remediation: Remediation | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "check_id": self.check_id,
            "check_name": self.check_name,
            "owasp": self.owasp.to_dict(),
            "severity": self.severity.value,
            "status": self.status.value,
            "depth": self.depth,
            "assessment_mode": self.assessment_mode,
            "evidence": self.evidence,
            "redacted": self.redacted,
        }
        if self.atlas:
            d["atlas"] = [a.to_dict() for a in self.atlas]
        if self.target_id is not None:
            d["target_id"] = self.target_id
        if self.host_config_path is not None:
            d["host_config_path"] = self.host_config_path
        if self.remediation is not None:
            d["remediation"] = self.remediation.to_dict()
        return d


@dataclass
class TargetSpec:
    """A Target under Assessment (from Host Config or explicit)."""

    target_id: str
    name: str | None = None
    transport: Transport = Transport.STDIO
    host: str | None = None
    host_config_path: str | None = None
    host_config_key: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    spawn: bool = True
    notes: list[str] = field(default_factory=list)

    def to_report_dict(self, *, spawned: bool | None = None) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "name": self.name,
            "transport": self.transport.value,
            "host": self.host,
            "host_config_path": self.host_config_path,
            "host_config_key": self.host_config_key,
            "command": self.command,
            "args": list(self.args),
            "url": self.url,
            "env_keys": sorted(self.env.keys()),
            "header_keys": sorted(self.headers.keys()),
            "spawned_stdio": spawned if spawned is not None else (
                self.spawn and self.transport == Transport.STDIO
            ),
            "notes": list(self.notes),
        }


@dataclass
class ToolInfo:
    name: str
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    capability_class: str = CapabilityClass.OTHER.value
    impact_class: str = ImpactClass.LOW.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "capability_class": self.capability_class,
            "impact_class": self.impact_class,
            "schema_gist": _schema_gist(self.input_schema),
        }


@dataclass
class ResourceInfo:
    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = None
    impact_class: str = ImpactClass.LOW.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
            "impact_class": self.impact_class,
        }


@dataclass
class PromptInfo:
    name: str
    description: str | None = None
    arguments: list[dict[str, Any]] | None = None
    impact_class: str = ImpactClass.LOW.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "arguments": self.arguments,
            "description_excerpt": (self.description or "")[:200],
            "impact_class": self.impact_class,
        }


@dataclass
class EnumeratedSurface:
    target_id: str
    protocol_version: str | None = None
    server_info: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    tools: list[ToolInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    resource_templates: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[PromptInfo] = field(default_factory=list)
    session_header_observed: bool = False
    connect_error: str | None = None
    enumerated: bool = False


def _schema_gist(schema: dict[str, Any] | None) -> str:
    if not schema:
        return ""
    props = schema.get("properties") or {}
    parts = []
    for name, prop in props.items():
        if isinstance(prop, dict):
            parts.append(f"{name}:{prop.get('type', '?')}")
        else:
            parts.append(str(name))
    return ", ".join(parts)
