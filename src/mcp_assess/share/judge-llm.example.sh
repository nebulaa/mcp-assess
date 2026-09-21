#!/usr/bin/env bash
# Example Judge template using Simon Willison's `llm` CLI.
# Set: export MCP_ASSESS_JUDGE_CMD="$(pwd)/share/judge-llm.example.sh"
# Or:  mcp-assess --judge-cmd '…/judge-llm.example.sh'
#
# Reads Judge request JSON from stdin; prints a single verdict JSON object.
set -euo pipefail
MODEL="${MCP_ASSESS_JUDGE_MODEL:-gpt-4.1-mini}"
REQUEST="$(cat)"
PROMPT=$(cat <<EOF
You are the mcp-assess Judge. Reply with ONLY a JSON object:
{"verdict":"clean|suspicious|poisoned|error","score":0-100,"rationale":"...","severity_hint":"low|medium|high|critical"|null}

Request:
$REQUEST
EOF
)
llm -m "$MODEL" "$PROMPT"
