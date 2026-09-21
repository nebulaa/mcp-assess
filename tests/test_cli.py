"""CLI smoke tests without live MCP Targets."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_assess.cli import main


def test_cli_help(capsys):
    try:
        main(["--help"])
    except SystemExit as e:
        assert e.code == 0
    out = capsys.readouterr().out
    assert "Assessment" in out or "mcp-assess" in out


def test_cli_no_targets_exits_2(tmp_path: Path, monkeypatch):
    # Point discovery at empty dir by using --config missing + no default? 
    # Use --url with --no-spawn doesn't apply. Use nonexistent config only.
    missing = tmp_path / "nope.json"
    out = tmp_path / "report"
    # Empty config file with no servers
    missing.write_text("{}", encoding="utf-8")
    code = main(["--config", str(missing), "--out", str(out), "--no-spawn"])
    assert code == 2
    assert Path(f"{out}.json").is_file()
    data = json.loads(Path(f"{out}.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["targets"] == []


def test_cli_config_secrets_finding(tmp_path: Path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "demo": {
                        "command": "false",
                        "args": [],
                        "env": {"API_TOKEN": "supersecretvalue12345678901234"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "report"
    # --no-spawn so we don't try to run `false` as MCP; config checks still run
    # but Enumerate won't happen — config checks run after enumerate loop.
    # With connect failure, assessed may be 0 → exit 2.
    # Put a URL-less STDIO with no-spawn: connect skipped, assessed=0 → exit 2.
    # Better: include only config that we don't spawn; runner still marks assessed=0.
    #
    # Adjust expectation: with only no-spawn STDIO, exit 2.
    # For secrets Finding we need assessed>0 OR change runner to still run config checks.
    # Looking at runner: if all no_spawn, assessed=0 and all have connect_error → exit 2
    # before checks. Fix runner to still run config checks when surfaces exist from no_spawn.
    code = main(
        [
            "--config",
            str(cfg),
            "--out",
            str(out),
            "--no-spawn",
        ]
    )
    assert Path(f"{out}.json").is_file()
    data = json.loads(Path(f"{out}.json").read_text(encoding="utf-8"))
    check_ids = {f["check_id"] for f in data.get("findings") or []}
    assert "CFG-SECRETS-HOST" in check_ids
    assert code in {0, 1}  # high Finding → 1
