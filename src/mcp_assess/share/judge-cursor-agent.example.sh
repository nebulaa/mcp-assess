#!/usr/bin/env bash
# Example Judge template using Cursor Agent CLI with {prompt_file}.
# Set:
#   export MCP_ASSESS_JUDGE_CMD='agent -p "$(cat {prompt_file})"'
# Or wrap this script and pass --judge-cmd with {prompt_file}.
#
# Placeholders substituted by mcp-assess: {prompt_file} {timeout_ms} {check_id} {subject_kind}
set -euo pipefail
PROMPT_FILE="${1:-}"
if [[ -z "$PROMPT_FILE" || ! -f "$PROMPT_FILE" ]]; then
  echo '{"verdict":"error","score":0,"rationale":"missing prompt_file","severity_hint":null}'
  exit 1
fi
# Prepend instruction; agent should emit JSON verdict as last object on stdout.
INSTRUCTION=$(cat <<'EOF'
You are the mcp-assess Judge. Read the JSON request below. Reply with ONLY a JSON object as the last thing you print:
{"verdict":"clean|suspicious|poisoned|error","score":0-100,"rationale":"...","severity_hint":"low|medium|high|critical"|null}
EOF
)
agent -p "$(printf '%s\n\n%s\n' "$INSTRUCTION" "$(cat "$PROMPT_FILE")")"
