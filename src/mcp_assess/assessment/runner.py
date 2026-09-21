"""Assessment orchestration."""

from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_assess import __version__
from mcp_assess.assessment.policy import InvokePolicy
from mcp_assess.checks.runner import (
    CheckContext,
    manual_checklist,
    run_config_checks,
    run_enumerate_checks,
    run_invoke_checks,
    run_judge_checks,
)
from mcp_assess.discovery.hosts import discover_targets, explicit_url_target
from mcp_assess.judge.shell import Judge
from mcp_assess.models import (
    AssessmentMode,
    EnumeratedSurface,
    FindingStatus,
    Severity,
    TargetSpec,
    Transport,
)
from mcp_assess.pins.store import PinStore
from mcp_assess.report.redact import redact_command_line
from mcp_assess.report.writer import write_report
from mcp_assess.surface.map import build_host_cross_server_map, build_surface_map
from mcp_assess.transport.client import open_client
from mcp_assess.transport.enumerate import enumerate_target


@dataclass
class AssessmentOptions:
    configs: list[Path] = field(default_factory=list)
    all_hosts: bool = False
    target_filters: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    bearer: str | None = None
    alt_targets: list[str] = field(default_factory=list)
    unsafe: bool = False
    probe_high_impact: bool = False
    high_impact_extra: list[str] = field(default_factory=list)
    high_impact_except: list[str] = field(default_factory=list)
    no_spawn: bool = False
    judge_cmd: str | None = None
    judge_timeout: float = 60.0
    judge_fail_fast: bool = False
    judge_verbose: bool = False
    pin_store: Path | None = None
    approve: bool = False
    approve_target: str | None = None
    out: Path = field(default_factory=lambda: Path("./mcp-assess-report"))
    json_only: bool = False
    md_only: bool = False
    show_secrets: bool = False
    argv: list[str] = field(default_factory=list)
    project_root: Path | None = None


@dataclass
class AssessmentResult:
    report: dict[str, Any]
    exit_code: int
    json_path: Path | None = None
    md_path: Path | None = None


async def run_assessment(opts: AssessmentOptions) -> AssessmentResult:
    started = datetime.now(timezone.utc)
    assessment_id = str(uuid.uuid4())
    mode = AssessmentMode.UNSAFE if opts.unsafe else AssessmentMode.SAFE
    policy = InvokePolicy(
        mode=mode,
        probe_high_impact=opts.probe_high_impact,
        high_impact_extra=list(opts.high_impact_extra),
        high_impact_except=set(opts.high_impact_except),
    )
    judge = Judge(
        opts.judge_cmd,
        timeout_sec=opts.judge_timeout,
        fail_fast=opts.judge_fail_fast,
        verbose=opts.judge_verbose,
    )
    pins = PinStore(opts.pin_store)

    notes: list[str] = []
    hosts_meta: list[dict[str, Any]] = []
    targets: list[TargetSpec] = []

    if opts.configs or opts.all_hosts or (
        not opts.urls and not opts.configs
    ):
        discovered, hosts_meta, disc_notes = discover_targets(
            all_hosts=opts.all_hosts,
            config_paths=opts.configs or None,
            project_root=opts.project_root,
            name_filter=opts.target_filters or None,
        )
        notes.extend(disc_notes)
        targets.extend(discovered)

    for url in opts.urls:
        targets.append(
            explicit_url_target(url, headers=opts.headers, bearer=opts.bearer)
        )

    for alt in opts.alt_targets:
        if mode != AssessmentMode.UNSAFE:
            notes.append(f"--alt-target ignored in Safe mode: {alt}")
            continue
        targets.append(
            explicit_url_target(
                alt, headers=opts.headers, bearer=opts.bearer
            )
        )

    if opts.no_spawn:
        for t in targets:
            t.spawn = False

    if not targets:
        report = _empty_report(
            started=started,
            opts=opts,
            mode=mode,
            policy=policy,
            judge=judge,
            pins=pins,
            hosts_meta=hosts_meta,
            notes=notes + ["No Targets discovered or supplied."],
        )
        jp, mp = write_report(
            report, opts.out, json_only=opts.json_only, md_only=opts.md_only
        )
        return AssessmentResult(report=report, exit_code=2, json_path=jp, md_path=mp)

    surfaces: dict[str, EnumeratedSurface] = {}
    clients_held: dict[str, Any] = {}
    client_cms: list[Any] = []
    spawned_any = False
    target_reports: list[dict[str, Any]] = []
    surface_maps: list[dict[str, Any]] = []
    assessed = 0

    try:
        for idx, target in enumerate(targets):
            tnotes = list(target.notes)
            if target.transport == Transport.STDIO and not target.spawn:
                tnotes.append("STDIO spawn disabled (--no-spawn)")
                surfaces[target.target_id] = EnumeratedSurface(
                    target_id=target.target_id,
                    connect_error="no_spawn",
                )
                sm = build_surface_map(
                    target,
                    surfaces[target.target_id],
                    surface_map_id=f"sm-{idx + 1}",
                    spawned=False,
                )
                surface_maps.append(sm)
                target_reports.append(target.to_report_dict(spawned=False))
                target_reports[-1]["notes"] = tnotes
                continue

            try:
                cm = open_client(target)
                client = await cm.__aenter__()
                client_cms.append(cm)
                clients_held[target.target_id] = client
                if target.transport == Transport.STDIO:
                    spawned_any = True
                    tnotes.append("Spawned STDIO with no OS sandbox (v1).")

                surf = await enumerate_target(
                    client,
                    target.target_id,
                    extra_patterns=policy.high_impact_extra,
                    except_names=policy.high_impact_except,
                )
                surfaces[target.target_id] = surf
                assessed += 1

                # Approve pins
                should_approve = opts.approve or (
                    opts.approve_target
                    and opts.approve_target
                    in {target.target_id, target.name or ""}
                )
                if should_approve and surf.enumerated:
                    pins.approve(
                        target_id=target.target_id,
                        host_config_path=target.host_config_path,
                        surface=surf,
                        assessment_id=assessment_id,
                    )
                    tnotes.append("Pin approved this run.")

                sm = build_surface_map(
                    target,
                    surf,
                    surface_map_id=f"sm-{idx + 1}",
                    spawned=target.transport == Transport.STDIO and target.spawn,
                )
                surface_maps.append(sm)
                target_reports.append(target.to_report_dict(spawned=spawned_any))
                target_reports[-1]["notes"] = tnotes

            except Exception as e:
                surfaces[target.target_id] = EnumeratedSurface(
                    target_id=target.target_id,
                    connect_error=str(e)[:500],
                )
                tnotes.append(f"Connect/Enumerate failed: {e}")
                sm = build_surface_map(
                    target,
                    surfaces[target.target_id],
                    surface_map_id=f"sm-{idx + 1}",
                    spawned=False,
                )
                surface_maps.append(sm)
                target_reports.append(target.to_report_dict(spawned=False))
                target_reports[-1]["notes"] = tnotes

        # Host-scoped cross-server map
        hosts = {t.host for t in targets if t.host}
        for host in hosts:
            host_targets = [t for t in targets if t.host == host]
            surface_maps.append(
                build_host_cross_server_map(
                    host or "unknown",
                    host_targets,
                    surfaces,
                    surface_map_id=f"sm-host-{host}",
                )
            )

        live_failed = assessed == 0 and all(
            bool(surfaces.get(t.target_id) and surfaces[t.target_id].connect_error)
            for t in targets
        )
        if live_failed:
            notes = notes + [
                "No live Enumerate succeeded (connect failed and/or --no-spawn); "
                "config Checks still ran."
            ]

        ctx = CheckContext(
            targets=targets,
            surfaces=surfaces,
            policy=policy,
            judge=judge,
            pins=pins,
            mode=mode.value,
            show_secrets=opts.show_secrets,
            clients=clients_held,
        )

        findings = []
        findings.extend(run_config_checks(ctx))
        if assessed > 0:
            findings.extend(run_enumerate_checks(ctx))
            try:
                findings.extend(run_judge_checks(ctx))
            except RuntimeError as e:
                finished = datetime.now(timezone.utc)
                report = {
                    "schema_version": 1,
                    "assessment": _assessment_meta(
                        started,
                        finished,
                        opts,
                        mode,
                        policy,
                        judge,
                        pins,
                        spawned_any,
                    ),
                    "hosts": hosts_meta,
                    "targets": target_reports,
                    "surface_maps": surface_maps,
                    "findings": [f.to_dict() for f in findings],
                    "manual_checks": manual_checklist(ctx),
                    "notes": notes + [str(e)],
                }
                jp, mp = write_report(
                    report, opts.out, json_only=opts.json_only, md_only=opts.md_only
                )
                return AssessmentResult(
                    report=report, exit_code=2, json_path=jp, md_path=mp
                )
            findings.extend(await run_invoke_checks(ctx))

        manuals = manual_checklist(ctx)

        finished = datetime.now(timezone.utc)
        report = {
            "schema_version": 1,
            "assessment": _assessment_meta(
                started, finished, opts, mode, policy, judge, pins, spawned_any
            ),
            "hosts": hosts_meta,
            "targets": target_reports,
            "surface_maps": surface_maps,
            "findings": [f.to_dict() for f in findings],
            "manual_checks": manuals,
            "notes": notes,
        }
        jp, mp = write_report(
            report, opts.out, json_only=opts.json_only, md_only=opts.md_only
        )
        # Exit 2 only when nothing was Assessed live AND no Targets were config-only complete
        if live_failed and not findings:
            exit_code = 2
        elif live_failed:
            # Config Findings present — still signal aborted live path if operator expected Enumerate
            # Laptop-first: prefer Finding-based exit when config Checks produced results.
            exit_code = _exit_code(findings)
        else:
            exit_code = _exit_code(findings)
        return AssessmentResult(
            report=report, exit_code=exit_code, json_path=jp, md_path=mp
        )
    finally:
        for cm in reversed(client_cms):
            try:
                await cm.__aexit__(*sys.exc_info())
            except Exception:
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:
                    pass


def _assessment_meta(
    started: datetime,
    finished: datetime,
    opts: AssessmentOptions,
    mode: AssessmentMode,
    policy: InvokePolicy,
    judge: Judge,
    pins: PinStore,
    spawned_stdio: bool,
) -> dict[str, Any]:
    return {
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "mode": mode.value,
        "high_impact_probes": opts.probe_high_impact,
        "judge_configured": judge.configured,
        "spawned_stdio": spawned_stdio,
        "secrets_redacted": not opts.show_secrets,
        "mcp_assess_version": __version__,
        "command_line": redact_command_line(
            opts.argv or sys.argv, show_secrets=opts.show_secrets
        ),
        "pin_store": str(pins.root),
        "invoke_policy": policy.to_dict(spawned_stdio=spawned_stdio),
        "no_sandbox": True,
    }


def _empty_report(
    *,
    started: datetime,
    opts: AssessmentOptions,
    mode: AssessmentMode,
    policy: InvokePolicy,
    judge: Judge,
    pins: PinStore,
    hosts_meta: list[dict[str, Any]],
    notes: list[str],
) -> dict[str, Any]:
    finished = datetime.now(timezone.utc)
    return {
        "schema_version": 1,
        "assessment": _assessment_meta(
            started, finished, opts, mode, policy, judge, pins, False
        ),
        "hosts": hosts_meta,
        "targets": [],
        "surface_maps": [],
        "findings": [],
        "manual_checks": [],
        "notes": notes,
    }


def _exit_code(findings: list) -> int:
    for f in findings:
        status = f.status if hasattr(f, "status") else FindingStatus(f.get("status"))
        severity = (
            f.severity if hasattr(f, "severity") else Severity(f.get("severity"))
        )
        if status == FindingStatus.FINDING and severity in {
            Severity.HIGH,
            Severity.CRITICAL,
        }:
            return 1
    return 0
