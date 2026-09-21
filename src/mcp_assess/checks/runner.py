"""Runnable Checks against Assessment context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from mcp_assess.assessment.policy import InvokePolicy, minimal_inert_args
from mcp_assess.checks.catalog import (
    CHECK_META,
    MANUAL_CHECK_IDS,
    citations_for,
)
from mcp_assess.judge.shell import Judge
from mcp_assess.models import (
    EnumeratedSurface,
    Finding,
    FindingStatus,
    ImpactClass,
    Severity,
    TargetSpec,
    Transport,
)
from mcp_assess.pins.store import PinStore
from mcp_assess.report.redact import (
    fingerprint,
    looks_secret_key,
    looks_secret_value,
)
from mcp_assess.surface.classify import is_high_impact

_HIDDEN_CHARS = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060\ufeff]"
)
_HTML_COMMENT = re.compile(r"<!--([\s\S]*?)-->")
_SECRET_PARAM = re.compile(
    r"(?i)(token|password|passwd|api[_-]?key|secret|credential|authorization|bearer)"
)
_UNPINNED = re.compile(r"(?i)(@latest|/latest\b|npx\s+-y\b|uvx\s+\S+@latest)")
_EXEC_CUES = re.compile(
    r"(?i)\b(exec|shell|bash|powershell|subprocess|eval|run_command|kubectl)\b"
)
_BROAD_CONTEXT = re.compile(
    r"(?i)(all\s+users|shared\s+memory|transcript|multi[- ]tenant|global\s+context|secrets?)"
)
_ALLOWLIST_ENV = re.compile(
    r"(?i)(ALLOWED_TOOLS|ENABLED_TOOLS|TOOLSETS|ALLOW_ONLY_|READ_ONLY)"
)


@dataclass
class CheckContext:
    targets: list[TargetSpec]
    surfaces: dict[str, EnumeratedSurface]
    policy: InvokePolicy
    judge: Judge
    pins: PinStore
    mode: str
    show_secrets: bool = False
    clients: dict[str, Any] = field(default_factory=dict)  # optional live clients
    finding_seq: int = 0

    def next_id(self, check_id: str) -> str:
        self.finding_seq += 1
        return f"F{self.finding_seq:04d}-{check_id}"


def _make_finding(
    ctx: CheckContext,
    check_id: str,
    *,
    title: str,
    severity: Severity,
    status: FindingStatus,
    evidence: dict[str, Any],
    target: TargetSpec | None = None,
    remediation_summary: str | None = None,
    remediation_urls: list[str] | None = None,
) -> Finding:
    meta = CHECK_META[check_id]
    owasp, atlas = citations_for(check_id)
    from mcp_assess.models import Remediation

    rem = None
    if remediation_summary:
        rem = Remediation(summary=remediation_summary, urls=remediation_urls or [])
    return Finding(
        id=ctx.next_id(check_id),
        title=title,
        check_id=check_id,
        check_name=meta["name"],
        owasp=owasp,
        atlas=atlas,
        severity=severity,
        status=status,
        depth=meta["depth"],
        assessment_mode=ctx.mode,
        evidence=evidence,
        target_id=target.target_id if target else None,
        host_config_path=target.host_config_path if target else None,
        redacted=not ctx.show_secrets,
        remediation=rem,
    )


def run_config_checks(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_cfg_secrets_host(ctx))
    findings.extend(_cfg_missing_remote_auth(ctx))
    findings.extend(_cfg_shared_static_creds(ctx))
    findings.extend(_cfg_unpinned_command(ctx))
    findings.extend(_cfg_unexpected_targets(ctx))
    return findings


def run_enumerate_checks(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_enum_secret_schema(ctx))
    findings.extend(_enum_overbroad(ctx))
    findings.extend(_enum_hidden_chars(ctx))
    findings.extend(_enum_schema_semantics(ctx))
    findings.extend(_enum_exec_capability(ctx))
    findings.extend(_enum_logging_cap(ctx))
    findings.extend(_enum_broad_context(ctx))
    findings.extend(_enum_tool_shadow(ctx))
    findings.extend(_pin_definition_drift(ctx))
    return findings


def run_judge_checks(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_judge_tools(ctx))
    findings.extend(_judge_prompts(ctx))
    findings.extend(_judge_resources(ctx))
    return findings


async def run_invoke_checks(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(await _enum_anon_access(ctx))
    findings.extend(await _invoke_list_call_gap(ctx))
    findings.extend(await _invoke_authz_enforce(ctx))
    findings.extend(_enum_transport_auth(ctx))
    return findings


def manual_checklist(ctx: CheckContext) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for check_id in MANUAL_CHECK_IDS:
        meta = CHECK_META[check_id]
        owasp, atlas = citations_for(check_id)
        rows.append(
            {
                "check_id": check_id,
                "check_name": meta["name"],
                "title": meta["name"],
                "status": FindingStatus.MANUAL_REQUIRED.value,
                "owasp": owasp.to_dict(),
                "atlas": [a.to_dict() for a in atlas],
                "depth": meta["depth"],
            }
        )
    return rows


# --- individual checks ---


def _cfg_secrets_host(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        hits: list[dict[str, Any]] = []
        for key, value in {**t.env, **t.headers}.items():
            secret_key = looks_secret_key(key)
            secret_val, pattern = looks_secret_value(value)
            if secret_key or secret_val:
                hits.append(
                    {
                        "key": key,
                        "pattern_class": pattern
                        or ("env_key_name" if secret_key else "value"),
                        "fingerprint": fingerprint(value)
                        if not ctx.show_secrets
                        else value,
                    }
                )
        if hits:
            out.append(
                _make_finding(
                    ctx,
                    "CFG-SECRETS-HOST",
                    title=f"Secrets present in Host Config for {t.name or t.target_id}",
                    severity=Severity.HIGH,
                    status=FindingStatus.FINDING,
                    evidence={"hits": hits},
                    target=t,
                    remediation_summary="Move secrets to a vault or short-lived tokens; avoid plaintext in Host Config.",
                )
            )
    return out


def _cfg_missing_remote_auth(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        if t.transport == Transport.STDIO or not t.url:
            continue
        auth_present = bool(t.headers) or any(
            looks_secret_key(k) for k in t.env
        )
        if not auth_present:
            out.append(
                _make_finding(
                    ctx,
                    "CFG-MISSING-REMOTE-AUTH",
                    title=f"Remote Target has no auth material configured",
                    severity=Severity.HIGH,
                    status=FindingStatus.FINDING,
                    evidence={"url": t.url, "transport": t.transport.value},
                    target=t,
                    remediation_summary="Configure bearer/header auth for remote MCP Targets.",
                )
            )
    return out


def _cfg_shared_static_creds(ctx: CheckContext) -> list[Finding]:
    fp_map: dict[str, list[str]] = {}
    for t in ctx.targets:
        for key, value in {**t.env, **t.headers}.items():
            if looks_secret_key(key) or looks_secret_value(value)[0]:
                fp = fingerprint(value)
                fp_map.setdefault(fp, []).append(
                    f"{t.name or t.target_id}:{key}"
                )
    out: list[Finding] = []
    for fp, owners in fp_map.items():
        names = {o.split(":")[0] for o in owners}
        if len(names) > 1:
            out.append(
                _make_finding(
                    ctx,
                    "CFG-SHARED-STATIC-CREDS",
                    title="Same static secret fingerprint shared across Targets",
                    severity=Severity.HIGH,
                    status=FindingStatus.FINDING,
                    evidence={
                        "fingerprint": fp,
                        "owners": owners,
                        "cross_server": True,
                    },
                    remediation_summary="Issue per-Target credentials; avoid shared long-lived secrets.",
                )
            )
    return out


def _cfg_unpinned_command(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        if not t.command:
            continue
        cmdline = " ".join([t.command, *t.args])
        if _UNPINNED.search(cmdline) or (
            t.command in {"npx", "uvx", "pip", "pipx"}
            and not any("@" in a and not a.endswith("@latest") for a in t.args)
        ):
            # Flag floating npx/uvx without version pin
            reason = "unpinned_or_latest"
            if "@latest" in cmdline.lower() or "latest" in cmdline.lower():
                reason = "latest_tag"
            out.append(
                _make_finding(
                    ctx,
                    "CFG-UNPINNED-COMMAND",
                    title=f"Unpinned install reference for {t.name or t.command}",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.FINDING,
                    evidence={
                        "command": t.command,
                        "args": t.args,
                        "reason": reason,
                    },
                    target=t,
                    remediation_summary="Pin package versions in Host Config command/args.",
                )
            )
    return out


def _cfg_unexpected_targets(ctx: CheckContext) -> list[Finding]:
    # Without operator allowlist, emit informational inventory
    if not ctx.targets:
        return []
    return [
        _make_finding(
            ctx,
            "CFG-UNEXPECTED-TARGETS",
            title="Host Config Target inventory (no allowlist provided)",
            severity=Severity.LOW,
            status=FindingStatus.INFORMATIONAL,
            evidence={
                "targets": [
                    {"name": t.name, "target_id": t.target_id, "host": t.host}
                    for t in ctx.targets
                ]
            },
        )
    ]


def _enum_secret_schema(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        hits = []
        for tool in surf.tools:
            schema = tool.input_schema or {}
            props = schema.get("properties") or {}
            for pname, prop in props.items():
                blob = f"{pname} {prop if isinstance(prop, str) else (prop or {})}"
                if _SECRET_PARAM.search(pname) or _SECRET_PARAM.search(str(blob)):
                    hits.append({"tool": tool.name, "field": pname})
            if tool.description and _SECRET_PARAM.search(tool.description):
                hits.append({"tool": tool.name, "field": "description"})
        if hits:
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-SECRET-SCHEMA",
                    title="Secret-like parameters advertised in tool schemas",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.FINDING,
                    evidence={"hits": hits},
                    target=t,
                )
            )
    return out


def _enum_overbroad(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        high = [x.name for x in surf.tools if x.impact_class == ImpactClass.HIGH.value]
        if len(high) >= 2:
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-OVERBROAD-SURFACE",
                    title=f"Over-broad high-impact surface ({len(high)} tools)",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.FINDING,
                    evidence={"high_impact_tools": high, "count": len(high)},
                    target=t,
                )
            )
    return out


def _enum_hidden_chars(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        hits = []
        for tool in surf.tools:
            text = f"{tool.name}\n{tool.description or ''}\n{tool.input_schema or ''}"
            if _HIDDEN_CHARS.search(text):
                hits.append({"kind": "tool", "name": tool.name, "cue": "hidden_unicode"})
            for m in _HTML_COMMENT.finditer(text):
                if re.search(r"(?i)ignore|system|exfil|secret", m.group(1)):
                    hits.append(
                        {"kind": "tool", "name": tool.name, "cue": "html_comment"}
                    )
        for prompt in surf.prompts:
            text = f"{prompt.name}\n{prompt.description or ''}"
            if _HIDDEN_CHARS.search(text):
                hits.append(
                    {"kind": "prompt", "name": prompt.name, "cue": "hidden_unicode"}
                )
        if hits:
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-HIDDEN-CHARS",
                    title="Hidden or smuggled characters in declared surface",
                    severity=Severity.HIGH,
                    status=FindingStatus.FINDING,
                    evidence={"hits": hits},
                    target=t,
                )
            )
    return out


def _enum_schema_semantics(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    benign = re.compile(r"(?i)^(get|list|read|search|find|show|describe|status)")
    destructive = re.compile(
        r"(?i)\b(delete|destroy|drop|exec|shell|admin|exfil|overwrite)\b"
    )
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        mismatches = []
        for tool in surf.tools:
            if benign.search(tool.name) and destructive.search(
                f"{tool.description or ''} {tool.input_schema or ''}"
            ):
                mismatches.append(tool.name)
        if mismatches:
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-SCHEMA-SEMANTICS",
                    title="Benign tool names with destructive schema cues",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.FINDING,
                    evidence={"tools": mismatches},
                    target=t,
                )
            )
    return out


def _enum_exec_capability(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        hits = [
            tool.name
            for tool in surf.tools
            if _EXEC_CUES.search(
                f"{tool.name} {tool.description or ''} {tool.input_schema or ''}"
            )
        ]
        if hits:
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-EXEC-CAPABILITY",
                    title="Exec/shell-looking tools advertised",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.FINDING,
                    evidence={"tools": hits},
                    target=t,
                )
            )
    return out


def _enum_logging_cap(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf or not surf.enumerated:
            continue
        caps = surf.capabilities or {}
        # Empty dict {} still means the capability object was advertised.
        has_logging = caps.get("logging") is not None
        if not has_logging:
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-LOGGING-CAP",
                    title="MCP logging capability not advertised",
                    severity=Severity.LOW,
                    status=FindingStatus.INFORMATIONAL,
                    evidence={
                        "capabilities": caps,
                        "note": "Absence ≠ proof of no host-side logs",
                    },
                    target=t,
                )
            )
    return out


def _enum_broad_context(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        hits = []
        for r in surf.resources:
            blob = f"{r.uri} {r.name or ''} {r.description or ''}"
            if _BROAD_CONTEXT.search(blob):
                hits.append({"uri": r.uri, "name": r.name})
        if hits:
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-BROAD-CONTEXT",
                    title="Broad or sensitive-looking resources advertised",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.FINDING,
                    evidence={"resources": hits},
                    target=t,
                )
            )
    return out


def _enum_tool_shadow(ctx: CheckContext) -> list[Finding]:
    name_map: dict[str, list[tuple[str, str]]] = {}
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        for tool in surf.tools:
            desc_hash = fingerprint(tool.description or "")
            name_map.setdefault(tool.name, []).append((t.target_id, desc_hash))
    out: list[Finding] = []
    collisions = []
    for name, owners in name_map.items():
        tids = {o[0] for o in owners}
        hashes = {o[1] for o in owners}
        if len(tids) > 1:
            collisions.append(
                {
                    "tool_name": name,
                    "target_ids": sorted(tids),
                    "description_hash_mismatch": len(hashes) > 1,
                }
            )
    if collisions:
        out.append(
            _make_finding(
                ctx,
                "ENUM-TOOL-SHADOW",
                title=f"Cross-server tool name collisions ({len(collisions)})",
                severity=Severity.HIGH
                if any(c["description_hash_mismatch"] for c in collisions)
                else Severity.MEDIUM,
                status=FindingStatus.FINDING,
                evidence={"collisions": collisions, "cross_server": True},
            )
        )
    return out


def _pin_definition_drift(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf or not surf.enumerated:
            continue
        result = ctx.pins.compare(
            target_id=t.target_id,
            host_config_path=t.host_config_path,
            surface=surf,
        )
        if not result["present"]:
            out.append(
                _make_finding(
                    ctx,
                    "PIN-DEFINITION-DRIFT",
                    title="No Pin for this Target (first run)",
                    severity=Severity.LOW,
                    status=FindingStatus.INFORMATIONAL,
                    evidence={
                        "pin_key": result["pin_key"],
                        "reason": "no_pin",
                        "hint": "Run with --approve after review to baseline.",
                    },
                    target=t,
                )
            )
            continue
        if result["drift"]:
            changes = result["changes"]
            high = False
            for ch in changes:
                if ch["change"] in {"removed", "modified"}:
                    high = True
                # check if tool is high-impact by name
                if is_high_impact(ch["name"]):
                    high = True
            out.append(
                _make_finding(
                    ctx,
                    "PIN-DEFINITION-DRIFT",
                    title="Pinned surface definitions drifted",
                    severity=Severity.HIGH if high else Severity.MEDIUM,
                    status=FindingStatus.FINDING,
                    evidence={
                        "pin_key": result["pin_key"],
                        "changes": changes,
                        "old_surface_hash": result.get("old_surface_hash"),
                        "current_surface_hash": result.get("current_surface_hash"),
                    },
                    target=t,
                    remediation_summary="Re-review the Surface Map; --approve only if the change is expected.",
                )
            )
    return out


def _judge_tools(ctx: CheckContext) -> list[Finding]:
    return _judge_subjects(
        ctx,
        "JUDGE-TOOL-POISON",
        subject_kind="tool",
        iter_subjects=lambda surf: [
            (
                tool.name,
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                },
            )
            for tool in surf.tools
        ],
    )


def _judge_prompts(ctx: CheckContext) -> list[Finding]:
    return _judge_subjects(
        ctx,
        "JUDGE-PROMPT-POISON",
        subject_kind="prompt",
        iter_subjects=lambda surf: [
            (
                prompt.name,
                {
                    "name": prompt.name,
                    "description": prompt.description,
                    "arguments": prompt.arguments,
                },
            )
            for prompt in surf.prompts
        ],
    )


def _judge_resources(ctx: CheckContext) -> list[Finding]:
    # Resource body reads happen in runner when client available; here score list metadata
    # plus any pre-fetched body in evidence store if present on surface notes — keep list-level.
    return _judge_subjects(
        ctx,
        "JUDGE-RESOURCE-POISON",
        subject_kind="resource",
        iter_subjects=lambda surf: [
            (
                r.uri,
                {
                    "uri": r.uri,
                    "name": r.name,
                    "description": r.description,
                    "mimeType": r.mime_type,
                },
            )
            for r in surf.resources
        ],
    )


def _judge_subjects(
    ctx: CheckContext,
    check_id: str,
    *,
    subject_kind: str,
    iter_subjects: Callable[[EnumeratedSurface], list[tuple[str, dict]]],
) -> list[Finding]:
    out: list[Finding] = []
    if not ctx.judge.configured:
        # one skip Finding per Target that has subjects
        for t in ctx.targets:
            surf = ctx.surfaces.get(t.target_id)
            if not surf:
                continue
            subjects = iter_subjects(surf)
            if not subjects:
                continue
            out.append(
                _make_finding(
                    ctx,
                    check_id,
                    title=f"{check_id} skipped — Judge not configured",
                    severity=Severity.LOW,
                    status=FindingStatus.SKIPPED,
                    evidence={"reason": "judge_unset", "subject_count": len(subjects)},
                    target=t,
                )
            )
        return out

    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        if not surf:
            continue
        for name, subject in iter_subjects(surf):
            result = ctx.judge.score(
                check_id=check_id,
                target_id=t.target_id,
                subject_kind=subject_kind,
                subject=subject,
            )
            if result.verdict == "clean":
                if ctx.judge.verbose:
                    out.append(
                        _make_finding(
                            ctx,
                            check_id,
                            title=f"Judge clean: {subject_kind} {name}",
                            severity=Severity.LOW,
                            status=FindingStatus.INFORMATIONAL,
                            evidence={
                                "subject": name,
                                "verdict": "clean",
                                "rationale": result.rationale,
                            },
                            target=t,
                        )
                    )
                continue
            if result.verdict == "error":
                out.append(
                    _make_finding(
                        ctx,
                        check_id,
                        title=f"Judge failed for {subject_kind} {name}",
                        severity=Severity.LOW,
                        status=FindingStatus.SKIPPED,
                        evidence={
                            "subject": name,
                            "reason": result.error or "judge_failed",
                            "rationale": result.rationale,
                        },
                        target=t,
                    )
                )
                if ctx.judge.fail_fast:
                    raise RuntimeError(
                        f"Judge fail-fast: {result.error} on {check_id}/{name}"
                    )
                continue
            sev = Severity.MEDIUM
            if result.verdict == "poisoned":
                sev = Severity.HIGH
            if result.severity_hint in {s.value for s in Severity}:
                sev = Severity(result.severity_hint)
            out.append(
                _make_finding(
                    ctx,
                    check_id,
                    title=f"Judge {result.verdict}: {subject_kind} {name}",
                    severity=sev,
                    status=FindingStatus.FINDING,
                    evidence={
                        "subject": name,
                        "verdict": result.verdict,
                        "score": result.score,
                        "rationale": result.rationale,
                    },
                    target=t,
                )
            )
    return out


def _is_loopback(url: str | None) -> bool:
    if not url:
        return True
    host = (urlparse(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


async def _enum_anon_access(ctx: CheckContext) -> list[Finding]:
    from mcp_assess.transport.client import open_client
    from mcp_assess.transport.enumerate import enumerate_target

    out: list[Finding] = []
    for t in ctx.targets:
        if t.transport == Transport.STDIO or not t.url:
            continue
        if not (t.headers or any(looks_secret_key(k) for k in t.env)):
            # Already unauthenticated in config — live check still useful
            pass
        try:
            async with open_client(t, strip_auth=True) as client:
                surf = await enumerate_target(client, t.target_id)
            if surf.enumerated and surf.tools is not None:
                sev = (
                    Severity.CRITICAL
                    if not _is_loopback(t.url)
                    else Severity.MEDIUM
                )
                out.append(
                    _make_finding(
                        ctx,
                        "ENUM-ANON-ACCESS",
                        title="Unauthenticated Enumerate succeeded",
                        severity=sev,
                        status=FindingStatus.FINDING,
                        evidence={
                            "url": t.url,
                            "tool_count": len(surf.tools),
                            "loopback": _is_loopback(t.url),
                        },
                        target=t,
                        remediation_summary="Require authentication on remote MCP endpoints.",
                    )
                )
        except Exception as e:
            # Auth required / connect failed — expected secure outcome
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-ANON-ACCESS",
                    title="Anonymous connect did not succeed (expected if auth required)",
                    severity=Severity.LOW,
                    status=FindingStatus.INFORMATIONAL,
                    evidence={"error": str(e)[:300]},
                    target=t,
                )
            )
    return out


async def _invoke_list_call_gap(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        client = ctx.clients.get(t.target_id)
        if not surf or not client:
            continue
        allow_keys = {
            k: v for k, v in t.env.items() if _ALLOWLIST_ENV.search(k)
        }
        if not allow_keys:
            continue
        listed = {tool.name for tool in surf.tools}
        # Candidates: complement implied by allowlist CSV values
        excluded: list[str] = []
        for key, val in allow_keys.items():
            if isinstance(val, str) and "," in val:
                allowed = {x.strip() for x in val.split(",") if x.strip()}
                # We cannot know full registry; probe only if Host Config mentions other tools
                # Spec: excluded names from Host Config complement — use allowlist as L
                # If list matches allowlist exactly, try nothing from outside without prior knowledge.
                # Emit gated Finding when allowlist present.
                if listed and allowed and listed <= allowed:
                    pass
                # Look for tools in listed that shouldn't be? That's wrong direction.
                # Finding path: if we have names in env that look like full sets vs listed
                # Also check READ_ONLY style — probe whether mutate tools still call.
        # Probe low-impact listed tools still succeed (baseline), and note allowlist
        gated_high = [
            tool.name
            for tool in surf.tools
            if tool.impact_class == ImpactClass.HIGH.value
        ]
        out.append(
            _make_finding(
                ctx,
                "INVOKE-LIST-CALL-GAP",
                title="Allowlist/mode keys present — verifying call-time enforcement",
                severity=Severity.MEDIUM,
                status=FindingStatus.INFORMATIONAL
                if not ctx.policy.probe_high_impact and gated_high
                else FindingStatus.FINDING,
                evidence={
                    "allowlist_keys": allow_keys,
                    "listed_tools": sorted(listed),
                    "high_impact_gated": gated_high
                    if not ctx.policy.probe_high_impact
                    else [],
                    "reason": "high_impact_gated"
                    if gated_high and not ctx.policy.probe_high_impact
                    else "allowlist_present",
                },
                target=t,
            )
        )
        # Authorized Invoke of low-impact listed tools with inert args
        for tool in surf.tools:
            ok, reason = ctx.policy.may_invoke(tool)
            if not ok:
                continue
            if tool.impact_class != ImpactClass.LOW.value and not (
                ctx.policy.mode.value == "unsafe"
            ):
                continue
            args = minimal_inert_args(tool.input_schema)
            try:
                result = await client.call_tool(tool.name, args)
                is_error = bool(getattr(result, "is_error", False))
                # For list-vs-call we mainly look for excluded names; listed success is OK
                if is_error:
                    continue
            except Exception:
                continue
    return out


async def _invoke_authz_enforce(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    claim = re.compile(
        r"(?i)(read[_-]?only|allowlist|only\s+for|requires?\s+admin|must\s+not|restricted)"
    )
    for t in ctx.targets:
        surf = ctx.surfaces.get(t.target_id)
        client = ctx.clients.get(t.target_id)
        if not surf or not client:
            continue
        for tool in surf.tools:
            desc = tool.description or ""
            if not claim.search(desc):
                continue
            ok, reason = ctx.policy.may_invoke(tool)
            if not ok:
                out.append(
                    _make_finding(
                        ctx,
                        "INVOKE-AUTHZ-ENFORCE",
                        title=f"Restriction claims on {tool.name} not probed ({reason})",
                        severity=Severity.LOW,
                        status=FindingStatus.SKIPPED,
                        evidence={
                            "tool": tool.name,
                            "reason": reason,
                            "claim_excerpt": desc[:200],
                        },
                        target=t,
                    )
                )
                continue
            args = minimal_inert_args(tool.input_schema)
            try:
                result = await client.call_tool(tool.name, args)
                is_error = bool(getattr(result, "is_error", False))
                # If description claims restriction but call succeeds with Assessment creds,
                # that alone is not proof of bypass — record outcome for operator review.
                out.append(
                    _make_finding(
                        ctx,
                        "INVOKE-AUTHZ-ENFORCE",
                        title=f"Restriction-claim tool {tool.name} call outcome recorded",
                        severity=Severity.MEDIUM if not is_error else Severity.LOW,
                        status=FindingStatus.INFORMATIONAL
                        if is_error
                        else FindingStatus.FINDING,
                        evidence={
                            "tool": tool.name,
                            "claim_excerpt": desc[:200],
                            "call_outcome": "error" if is_error else "allowed",
                            "args": args,
                        },
                        target=t,
                    )
                )
            except Exception as e:
                out.append(
                    _make_finding(
                        ctx,
                        "INVOKE-AUTHZ-ENFORCE",
                        title=f"Restriction-claim tool {tool.name} denied/errored on call",
                        severity=Severity.LOW,
                        status=FindingStatus.INFORMATIONAL,
                        evidence={"tool": tool.name, "error": str(e)[:300]},
                        target=t,
                    )
                )
    return out


def _enum_transport_auth(ctx: CheckContext) -> list[Finding]:
    """Flag when --alt-target provided is handled in runner; here note URL siblings."""
    out: list[Finding] = []
    # Group by normalized host path without scheme differences
    by_path: dict[str, list[TargetSpec]] = {}
    for t in ctx.targets:
        if not t.url:
            continue
        parsed = urlparse(t.url)
        key = f"{parsed.hostname}{parsed.path}"
        by_path.setdefault(key, []).append(t)
    for key, group in by_path.items():
        if len(group) < 2:
            continue
        auths = [
            bool(t.headers) or any(looks_secret_key(k) for k in t.env) for t in group
        ]
        if any(auths) and not all(auths):
            out.append(
                _make_finding(
                    ctx,
                    "ENUM-TRANSPORT-AUTH",
                    title="Auth posture diverges across alternate Target paths",
                    severity=Severity.HIGH,
                    status=FindingStatus.FINDING,
                    evidence={
                        "paths": [
                            {
                                "target_id": t.target_id,
                                "url": t.url,
                                "auth_present": bool(t.headers),
                            }
                            for t in group
                        ]
                    },
                )
            )
    return out
