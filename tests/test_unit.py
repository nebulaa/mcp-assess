"""Unit tests for discovery, classify, pins, judge parse, report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_assess.discovery.hosts import entry_to_target, parse_host_config
from mcp_assess.discovery.target_id import (
    normalize_url,
    pin_key,
    target_id_for_stdio,
    target_id_for_url,
)
from mcp_assess.judge.shell import last_json_object
from mcp_assess.models import EnumeratedSurface, ToolInfo
from mcp_assess.pins.store import PinStore
from mcp_assess.report.redact import fingerprint, looks_secret_value
from mcp_assess.report.writer import render_markdown
from mcp_assess.surface.classify import impact_class, is_high_impact


def test_normalize_url_strips_query_and_default_port():
    assert (
        normalize_url("HTTPS://Example.com:443/mcp/?token=secret")
        == "https://example.com/mcp"
    )


def test_target_id_stdio_includes_host_config():
    tid = target_id_for_stdio(
        "npx",
        ["-y", "pkg"],
        host_config_path="/tmp/mcp.json",
    )
    assert tid.startswith("stdio:npx -y pkg")
    assert "host_config:" in tid


def test_target_id_url_explicit_no_host():
    tid = target_id_for_url("https://mcp.example/mcp")
    assert tid == "url:https://mcp.example/mcp"
    assert pin_key(tid) == "url:https://mcp.example/mcp|host_config:"


def test_parse_cursor_style_config(tmp_path: Path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                        "env": {"API_TOKEN": "supersecretvalue1234567890"},
                    },
                    "remote": {
                        "url": "https://mcp.example/mcp",
                        "headers": {"Authorization": "Bearer abcdefghijklmnop"},
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    targets, notes = parse_host_config(cfg, host="cursor")
    assert "fs" in targets
    assert "remote" in targets
    assert targets["fs"].transport.value == "stdio"
    assert targets["remote"].url.endswith("/mcp")


def test_entry_to_target_vscode_servers_key(tmp_path: Path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "servers": {
                    "httpbin": {
                        "type": "http",
                        "url": "http://127.0.0.1:8000/mcp",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    targets, _ = parse_host_config(cfg, host="vscode")
    assert "httpbin" in targets
    assert targets["httpbin"].transport.value == "streamable_http"


def test_high_impact_classifier():
    assert is_high_impact("write_file", "writes a file")
    assert is_high_impact("run_shell", "executes shell")
    assert not is_high_impact("list_directory", "lists files")
    assert impact_class("delete_ticket") == "high-impact"
    assert impact_class("get_ticket") == "low"


def test_secret_detection():
    assert looks_secret_value("AKIAIOSFODNN7EXAMPLE")[0]
    assert looks_secret_value("short")[0] is False
    fp = fingerprint("secret-token-value-here")
    assert fp.startswith("sha256:")
    assert "…" in fp


def test_last_json_object_with_chatter():
    text = 'Thinking...\n{"verdict":"clean","score":1,"rationale":"ok"}\n'
    obj = last_json_object(text)
    assert obj is not None
    assert obj["verdict"] == "clean"


def test_pin_store_approve_and_drift(tmp_path: Path):
    store = PinStore(tmp_path / "pins")
    surface = EnumeratedSurface(
        target_id="url:https://ex/mcp",
        tools=[
            ToolInfo(name="get", description="d", input_schema={"type": "object"}),
        ],
        enumerated=True,
    )
    store.approve(
        target_id="url:https://ex/mcp",
        host_config_path=None,
        surface=surface,
    )
    cmp1 = store.compare(
        target_id="url:https://ex/mcp",
        host_config_path=None,
        surface=surface,
    )
    assert cmp1["present"] and not cmp1["drift"]

    surface2 = EnumeratedSurface(
        target_id="url:https://ex/mcp",
        tools=[
            ToolInfo(name="get", description="CHANGED", input_schema={"type": "object"}),
        ],
        enumerated=True,
    )
    cmp2 = store.compare(
        target_id="url:https://ex/mcp",
        host_config_path=None,
        surface=surface2,
    )
    assert cmp2["drift"]
    assert any(c["change"] == "modified" for c in cmp2["changes"])


def test_render_markdown_minimal():
    report = {
        "schema_version": 1,
        "assessment": {
            "started_at": "t0",
            "finished_at": "t1",
            "mode": "safe",
            "high_impact_probes": False,
            "judge_configured": False,
            "spawned_stdio": False,
            "secrets_redacted": True,
            "mcp_assess_version": "0.1.0",
            "command_line": "mcp-assess",
            "pin_store": "/tmp/pins",
        },
        "hosts": [],
        "targets": [],
        "surface_maps": [],
        "findings": [],
        "manual_checks": [],
    }
    md = render_markdown(report)
    assert "## Assessment" in md
    assert "## Findings" in md
