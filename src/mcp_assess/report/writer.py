"""Write Assessment Report as JSON + markdown."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_report(
    report: dict[str, Any],
    out: Path,
    *,
    json_only: bool = False,
    md_only: bool = False,
) -> tuple[Path | None, Path | None]:
    out = Path(out)
    if out.suffix in {".json", ".md"}:
        stem = out.with_suffix("")
    else:
        stem = out

    stem.parent.mkdir(parents=True, exist_ok=True)
    json_path = Path(f"{stem}.json")
    md_path = Path(f"{stem}.md")

    written_json = written_md = None
    if not md_only:
        json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written_json = json_path
    if not json_only:
        md_path.write_text(render_markdown(report), encoding="utf-8")
        written_md = md_path
    return written_json, written_md


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = ["# mcp-assess Report", ""]
    a = report.get("assessment") or {}
    lines += [
        "## Assessment",
        "",
        f"- **schema_version:** {report.get('schema_version')}",
        f"- **started_at:** {a.get('started_at')}",
        f"- **finished_at:** {a.get('finished_at')}",
        f"- **mode:** {a.get('mode')}",
        f"- **high_impact_probes:** {a.get('high_impact_probes')}",
        f"- **judge_configured:** {a.get('judge_configured')}",
        f"- **spawned_stdio:** {a.get('spawned_stdio')}",
        f"- **secrets_redacted:** {a.get('secrets_redacted')}",
        f"- **mcp_assess_version:** {a.get('mcp_assess_version')}",
        f"- **command_line:** `{a.get('command_line', '')}`",
        f"- **pin_store:** `{a.get('pin_store', '')}`",
        "",
    ]
    ip = a.get("invoke_policy") or {}
    if ip:
        lines += [
            "### Invoke policy",
            "",
            f"- classifier: `{ip.get('classifier_id')}`",
            f"- mode: `{ip.get('mode')}`",
            f"- high_impact_probes: {ip.get('high_impact_probes')}",
            "",
        ]

    lines += ["## Hosts", ""]
    for h in report.get("hosts") or []:
        paths = ", ".join(f"`{p}`" for p in h.get("host_config_paths") or [])
        lines.append(f"- **{h.get('host')}** — {paths}")
    lines.append("")

    lines += ["## Targets", ""]
    for t in report.get("targets") or []:
        lines.append(
            f"- `{t.get('target_id')}` — transport `{t.get('transport')}`"
            + (f" (key `{t.get('host_config_key')}`)" if t.get("host_config_key") else "")
        )
        if t.get("notes"):
            for n in t["notes"]:
                lines.append(f"  - note: {n}")
    lines.append("")

    lines += ["## Surface Maps", ""]
    for sm in report.get("surface_maps") or []:
        scope = sm.get("scope", "target")
        lines.append(f"### `{sm.get('surface_map_id')}` ({scope})")
        lines.append("")
        if scope == "host":
            cs = sm.get("cross_server") or {}
            lines.append(f"- name collisions: {len(cs.get('name_collisions') or [])}")
            lines.append(
                f"- toxic-flow hypotheses: {len(cs.get('toxic_flow_hypotheses') or [])}"
            )
        else:
            lines.append(f"- target: `{sm.get('target_id')}`")
            init = sm.get("initialize") or {}
            caps = init.get("capabilities") or {}
            lines.append(
                f"- caps: tools={'✓' if caps.get('tools') else '✗'} · "
                f"resources={'✓' if caps.get('resources') else '✗'} · "
                f"prompts={'✓' if caps.get('prompts') else '✗'}"
            )
            tools = sm.get("tools") or []
            lines.append(f"- tools: {len(tools)}")
            for tool in tools[:30]:
                lines.append(
                    f"  - `{tool.get('name')}` [{tool.get('capability_class')}/"
                    f"{tool.get('impact_class')}]"
                )
            hyps = sm.get("weakness_hypotheses") or []
            if hyps:
                lines.append("- weakness hypotheses:")
                for h in hyps:
                    lines.append(f"  - ({h.get('area')}) {h.get('summary')}")
        lines.append("")

    findings = report.get("findings") or []
    lines += ["## Findings", ""]
    if not findings:
        lines.append("_No Findings._")
        lines.append("")
    else:
        by_sev: dict[str, list[dict[str, Any]]] = {}
        order = ["critical", "high", "medium", "low"]
        for f in findings:
            by_sev.setdefault(f.get("severity", "low"), []).append(f)
        for sev in order:
            group = by_sev.get(sev) or []
            if not group:
                continue
            lines.append(f"### {sev.upper()}")
            lines.append("")
            for f in group:
                _render_finding(lines, f)
            lines.append("")

    cross = [
        f
        for f in findings
        if f.get("check_id") in {"ENUM-TOOL-SHADOW"}
        or (f.get("evidence") or {}).get("cross_server")
        or f.get("target_id") is None
    ]
    lines += ["## Cross-server", ""]
    if not cross:
        lines.append("_No cross-server Findings._")
        lines.append("")
    else:
        for f in cross:
            _render_finding(lines, f)
        lines.append("")

    lines += ["## Manual checklist", ""]
    manuals = report.get("manual_checks") or []
    if not manuals:
        lines.append("_None._")
        lines.append("")
    else:
        for m in manuals:
            lines.append(
                f"- [ ] **{m.get('check_id')}** — {m.get('check_name')} "
                f"({(m.get('owasp') or {}).get('id', '')})"
            )
            if m.get("title"):
                lines.append(f"  - {m.get('title')}")
        lines.append("")

    return "\n".join(lines)


def _render_finding(lines: list[str], f: dict[str, Any]) -> None:
    lines.append(f"#### `{f.get('id')}` — {f.get('title')}")
    lines.append("")
    lines.append(f"- check: `{f.get('check_id')}` ({f.get('check_name')})")
    lines.append(f"- status: `{f.get('status')}` · severity: `{f.get('severity')}`")
    owasp = f.get("owasp") or {}
    lines.append(f"- OWASP: {owasp.get('id')} — {owasp.get('title')}")
    atlas = f.get("atlas") or []
    if atlas:
        lines.append(
            "- ATLAS: "
            + ", ".join(a.get("id", "") for a in atlas)
        )
    if f.get("target_id"):
        lines.append(f"- target: `{f.get('target_id')}`")
    rem = f.get("remediation")
    if rem:
        lines.append(f"- remediation: {rem.get('summary')}")
    evidence = f.get("evidence") or {}
    if evidence:
        lines.append(f"- evidence: `{json.dumps(evidence, ensure_ascii=False)[:500]}`")
    lines.append("")
