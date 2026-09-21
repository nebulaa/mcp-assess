"""mcp-assess CLI."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp_assess import __version__
from mcp_assess.assessment.runner import AssessmentOptions, run_assessment
from mcp_assess.pins.store import PinStore


def _parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"Header must be K:V, got: {value!r}"
        )
    key, _, val = value.partition(":")
    return key.strip(), val.strip()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-assess",
        description=(
            "Authorized MCP Assessment — discover Host Configs, map surfaces, "
            "run Checks, write JSON+markdown Report."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="command")

    # Default assessment flags also on parent so `mcp-assess --url …` works
    _add_assessment_flags(p)

    pin = sub.add_parser("pin", help="Inspect or manage the Pin store")
    pin_sub = pin.add_subparsers(dest="pin_command", required=True)
    pin_list = pin_sub.add_parser("list", help="List Pin keys")
    pin_list.add_argument(
        "--pin-store",
        type=Path,
        default=None,
        help="Pin store directory (default ~/.mcp-assess/pins)",
    )
    pin_show = pin_sub.add_parser("show", help="Show one Pin")
    pin_show.add_argument("pin_key", help="Pin key")
    pin_show.add_argument("--pin-store", type=Path, default=None)
    pin_del = pin_sub.add_parser("delete", help="Delete one Pin")
    pin_del.add_argument("pin_key", help="Pin key")
    pin_del.add_argument("--pin-store", type=Path, default=None)

    return p


def _add_assessment_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--config",
        action="append",
        type=Path,
        default=[],
        help="Host Config path (repeatable)",
    )
    p.add_argument(
        "--all-hosts",
        action="store_true",
        help="Discover Cursor + Claude Desktop + VS Code Host Configs",
    )
    p.add_argument(
        "--target",
        action="append",
        default=[],
        help="Filter Targets by name, url, or target_id (repeatable)",
    )
    p.add_argument(
        "--url",
        action="append",
        default=[],
        help="Explicit remote Target URL (repeatable)",
    )
    p.add_argument(
        "--header",
        action="append",
        default=[],
        help="Pass-through header K:V for URL Targets (repeatable)",
    )
    p.add_argument("--bearer", default=None, help="Authorization bearer token")
    p.add_argument(
        "--alt-target",
        action="append",
        default=[],
        help="Unsafe alternate-path probe URL (repeatable)",
    )
    p.add_argument("--unsafe", action="store_true", help="Enable Unsafe Assessment Mode")
    p.add_argument(
        "--probe-high-impact",
        action="store_true",
        help="Allow high-impact Invokes",
    )
    p.add_argument(
        "--high-impact-extra",
        action="append",
        default=[],
        help="Extra high-impact regex (repeatable)",
    )
    p.add_argument(
        "--high-impact-except",
        action="append",
        default=[],
        help="Tool name exempt from high-impact (repeatable)",
    )
    p.add_argument(
        "--no-spawn",
        action="store_true",
        help="Do not spawn STDIO Targets",
    )
    p.add_argument(
        "--judge-cmd",
        default=None,
        help="Judge shell command template (overrides MCP_ASSESS_JUDGE_CMD)",
    )
    p.add_argument(
        "--judge-timeout",
        type=float,
        default=60.0,
        help="Judge timeout seconds (default 60)",
    )
    p.add_argument(
        "--judge-fail-fast",
        action="store_true",
        help="Abort Assessment on Judge failure",
    )
    p.add_argument(
        "--judge-verbose",
        action="store_true",
        help="Emit informational Findings on Judge clean",
    )
    p.add_argument(
        "--pin-store",
        type=Path,
        default=None,
        help="Pin store directory (default ~/.mcp-assess/pins)",
    )
    p.add_argument(
        "--approve",
        action="store_true",
        help="Write/update Pins after Enumerate for Targets in this run",
    )
    p.add_argument(
        "--approve-target",
        default=None,
        help="Approve Pin for one Target id/name only",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("./mcp-assess-report"),
        help="Output path stem or directory (writes .json and .md)",
    )
    p.add_argument("--json-only", action="store_true")
    p.add_argument("--md-only", action="store_true")
    p.add_argument(
        "--show-secrets",
        action="store_true",
        help="Disable secret redaction in Report",
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "pin":
        return _cmd_pin(args)

    headers: dict[str, str] = {}
    for h in args.header or []:
        k, v = _parse_header(h)
        headers[k] = v

    judge_cmd = args.judge_cmd or os.environ.get("MCP_ASSESS_JUDGE_CMD")

    opts = AssessmentOptions(
        configs=list(args.config or []),
        all_hosts=bool(args.all_hosts),
        target_filters=list(args.target or []),
        urls=list(args.url or []),
        headers=headers,
        bearer=args.bearer,
        alt_targets=list(args.alt_target or []),
        unsafe=bool(args.unsafe),
        probe_high_impact=bool(args.probe_high_impact),
        high_impact_extra=list(args.high_impact_extra or []),
        high_impact_except=list(args.high_impact_except or []),
        no_spawn=bool(args.no_spawn),
        judge_cmd=judge_cmd,
        judge_timeout=float(args.judge_timeout),
        judge_fail_fast=bool(args.judge_fail_fast),
        judge_verbose=bool(args.judge_verbose),
        pin_store=args.pin_store,
        approve=bool(args.approve),
        approve_target=args.approve_target,
        out=args.out,
        json_only=bool(args.json_only),
        md_only=bool(args.md_only),
        show_secrets=bool(args.show_secrets),
        argv=["mcp-assess", *argv],
    )

    try:
        result = asyncio.run(run_assessment(opts))
    except KeyboardInterrupt:
        print("Aborted.", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Assessment aborted: {e}", file=sys.stderr)
        return 2

    if result.json_path:
        print(f"Wrote {result.json_path}")
    if result.md_path:
        print(f"Wrote {result.md_path}")
    findings = result.report.get("findings") or []
    high = sum(
        1
        for f in findings
        if f.get("status") == "finding"
        and f.get("severity") in {"high", "critical"}
    )
    print(
        f"Targets: {len(result.report.get('targets') or [])} · "
        f"Findings: {len(findings)} · high/critical: {high}"
    )
    return result.exit_code


def _cmd_pin(args: argparse.Namespace) -> int:
    store = PinStore(args.pin_store)
    if args.pin_command == "list":
        keys = store.list_keys()
        if not keys:
            print("(no pins)")
            return 0
        for k in keys:
            print(k)
        return 0
    if args.pin_command == "show":
        body = store.get(args.pin_key)
        if not body:
            print(f"Pin not found: {args.pin_key}", file=sys.stderr)
            return 2
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0
    if args.pin_command == "delete":
        ok = store.delete(args.pin_key)
        if not ok:
            print(f"Pin not found: {args.pin_key}", file=sys.stderr)
            return 2
        print(f"Deleted {args.pin_key}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
