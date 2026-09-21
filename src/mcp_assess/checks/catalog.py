"""OWASP primary + ATLAS secondary citation tables."""

from __future__ import annotations

from mcp_assess.models import AtlasCitation, OwaspCitation

OWASP: dict[str, OwaspCitation] = {
    "MCP01:2025": OwaspCitation(
        id="MCP01:2025",
        title="Token Mismanagement & Secret Exposure",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP02:2025": OwaspCitation(
        id="MCP02:2025",
        title="Privilege Escalation via Scope Creep",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP03:2025": OwaspCitation(
        id="MCP03:2025",
        title="Tool Poisoning",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP04:2025": OwaspCitation(
        id="MCP04:2025",
        title="Software Supply Chain Attacks & Dependency Tampering",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP05:2025": OwaspCitation(
        id="MCP05:2025",
        title="Command Injection & Execution",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP06:2025": OwaspCitation(
        id="MCP06:2025",
        title="Intent Flow Subversion",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP07:2025": OwaspCitation(
        id="MCP07:2025",
        title="Insufficient Authentication & Authorization",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP08:2025": OwaspCitation(
        id="MCP08:2025",
        title="Lack of Audit and Telemetry",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP09:2025": OwaspCitation(
        id="MCP09:2025",
        title="Shadow MCP Servers",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    "MCP10:2025": OwaspCitation(
        id="MCP10:2025",
        title="Context Injection & Over-Sharing",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
}

ATLAS_BY_OWASP: dict[str, list[AtlasCitation]] = {
    "MCP01:2025": [
        AtlasCitation("AML.T0083", "Credentials from AI Agent Configuration", "https://atlas.mitre.org/techniques/AML.T0083"),
        AtlasCitation("AML.T0002.002", "AI Agent Configuration", "https://atlas.mitre.org/techniques/AML.T0002.002"),
    ],
    "MCP02:2025": [
        AtlasCitation("AML.T0053", "AI Agent Tool Invocation", "https://atlas.mitre.org/techniques/AML.T0053"),
    ],
    "MCP03:2025": [
        AtlasCitation("AML.T0110", "AI Agent Tool Poisoning", "https://atlas.mitre.org/techniques/AML.T0110"),
        AtlasCitation("AML.T0110.000", "Definition and Instructions", "https://atlas.mitre.org/techniques/AML.T0110.000"),
    ],
    "MCP04:2025": [
        AtlasCitation("AML.T0010.005", "AI Agent Tool", "https://atlas.mitre.org/techniques/AML.T0010.005"),
        AtlasCitation("AML.T0109", "AI Supply Chain Rug Pull", "https://atlas.mitre.org/techniques/AML.T0109"),
    ],
    "MCP05:2025": [
        AtlasCitation("AML.T0050", "Command and Scripting Interpreter", "https://atlas.mitre.org/techniques/AML.T0050"),
        AtlasCitation("AML.T0053", "AI Agent Tool Invocation", "https://atlas.mitre.org/techniques/AML.T0053"),
    ],
    "MCP06:2025": [
        AtlasCitation("AML.T0051", "LLM Prompt Injection", "https://atlas.mitre.org/techniques/AML.T0051"),
        AtlasCitation("AML.T0051.001", "Indirect", "https://atlas.mitre.org/techniques/AML.T0051.001"),
    ],
    "MCP07:2025": [],  # no clean fit for AuthZ gap itself
    "MCP08:2025": [],
    "MCP09:2025": [],
    "MCP10:2025": [
        AtlasCitation("AML.T0057", "LLM Data Leakage", "https://atlas.mitre.org/techniques/AML.T0057"),
    ],
}

# Pin drift gets MCP03 + rug-pull
PIN_ATLAS = [
    AtlasCitation("AML.T0109", "AI Supply Chain Rug Pull", "https://atlas.mitre.org/techniques/AML.T0109"),
    AtlasCitation("AML.T0110", "AI Agent Tool Poisoning", "https://atlas.mitre.org/techniques/AML.T0110"),
]

CHECK_META: dict[str, dict] = {
    "CFG-SECRETS-HOST": {"name": "Secrets in Host Config", "owasp": "MCP01:2025", "depth": "light"},
    "ENUM-SECRET-SCHEMA": {"name": "Secret-like parameters in schemas", "owasp": "MCP01:2025", "depth": "light"},
    "MANUAL-TOKEN-HYGIENE": {"name": "Token lifetime & rotation review", "owasp": "MCP01:2025", "depth": "light"},
    "ENUM-OVERBROAD-SURFACE": {"name": "Over-broad / high-impact tool surface", "owasp": "MCP02:2025", "depth": "light"},
    "MANUAL-SCOPE-DRIFT": {"name": "Entitlement & expiry review", "owasp": "MCP02:2025", "depth": "light"},
    "JUDGE-TOOL-POISON": {"name": "Tool description / schema text poisoning", "owasp": "MCP03:2025", "depth": "deep"},
    "JUDGE-PROMPT-POISON": {"name": "Prompt template poisoning", "owasp": "MCP03:2025", "depth": "deep"},
    "JUDGE-RESOURCE-POISON": {"name": "Resource text as poisoned context", "owasp": "MCP03:2025", "depth": "deep"},
    "ENUM-HIDDEN-CHARS": {"name": "Hidden / smuggled characters", "owasp": "MCP03:2025", "depth": "deep"},
    "ENUM-TOOL-SHADOW": {"name": "Cross-server tool shadowing", "owasp": "MCP03:2025", "depth": "deep"},
    "PIN-DEFINITION-DRIFT": {"name": "Rug-pull / trusted-definition drift", "owasp": "MCP03:2025", "depth": "deep"},
    "ENUM-SCHEMA-SEMANTICS": {"name": "Benign label vs destructive schema cues", "owasp": "MCP03:2025", "depth": "deep"},
    "CFG-UNPINNED-COMMAND": {"name": "Unpinned / mutable Target install refs", "owasp": "MCP04:2025", "depth": "light"},
    "MANUAL-SUPPLY-CHAIN": {"name": "SBOM, signatures, registry trust", "owasp": "MCP04:2025", "depth": "light"},
    "ENUM-EXEC-CAPABILITY": {"name": "Exec / shell / eval-looking tools", "owasp": "MCP05:2025", "depth": "light"},
    "MANUAL-SAFE-EXEC": {"name": "Parameterization & sandbox review", "owasp": "MCP05:2025", "depth": "light"},
    "JUDGE-INTENT-CONTEXT": {"name": "Goal-hijack instructions in context", "owasp": "MCP06:2025", "depth": "light"},
    "MANUAL-INTENT-ANCHOR": {"name": "Intent anchoring / PDP / HITL controls", "owasp": "MCP06:2025", "depth": "light"},
    "CFG-MISSING-REMOTE-AUTH": {"name": "Remote Target without auth material", "owasp": "MCP07:2025", "depth": "deep"},
    "ENUM-ANON-ACCESS": {"name": "Unauthenticated session succeeds", "owasp": "MCP07:2025", "depth": "deep"},
    "INVOKE-LIST-CALL-GAP": {"name": "List vs call authorization gap", "owasp": "MCP07:2025", "depth": "deep"},
    "INVOKE-AUTHZ-ENFORCE": {"name": "Presentation vs execution enforcement", "owasp": "MCP07:2025", "depth": "deep"},
    "ENUM-TRANSPORT-AUTH": {"name": "Transport / auth posture divergence", "owasp": "MCP07:2025", "depth": "deep"},
    "CFG-SHARED-STATIC-CREDS": {"name": "Shared static secrets across Targets", "owasp": "MCP07:2025", "depth": "deep"},
    "MANUAL-IAM-MTLS": {"name": "Org IAM / mTLS / RBAC review", "owasp": "MCP07:2025", "depth": "deep"},
    "ENUM-LOGGING-CAP": {"name": "Logging capability advertisement", "owasp": "MCP08:2025", "depth": "light"},
    "MANUAL-TELEMETRY": {"name": "Host & SIEM audit coverage", "owasp": "MCP08:2025", "depth": "light"},
    "CFG-UNEXPECTED-TARGETS": {"name": "Host Config inventory vs allowlist", "owasp": "MCP09:2025", "depth": "light"},
    "MANUAL-SHADOW-INVENTORY": {"name": "Org-wide shadow discovery", "owasp": "MCP09:2025", "depth": "light"},
    "ENUM-BROAD-CONTEXT": {"name": "Broad or sensitive-looking resources", "owasp": "MCP10:2025", "depth": "light"},
    "MANUAL-CONTEXT-ISOLATION": {"name": "Session / tenant isolation review", "owasp": "MCP10:2025", "depth": "light"},
}

MANUAL_CHECK_IDS = [
    "MANUAL-TOKEN-HYGIENE",
    "MANUAL-SCOPE-DRIFT",
    "MANUAL-SUPPLY-CHAIN",
    "MANUAL-SAFE-EXEC",
    "MANUAL-INTENT-ANCHOR",
    "MANUAL-IAM-MTLS",
    "MANUAL-TELEMETRY",
    "MANUAL-SHADOW-INVENTORY",
    "MANUAL-CONTEXT-ISOLATION",
]


def citations_for(check_id: str) -> tuple[OwaspCitation, list[AtlasCitation]]:
    meta = CHECK_META[check_id]
    owasp_id = meta["owasp"]
    owasp = OWASP[owasp_id]
    atlas = list(ATLAS_BY_OWASP.get(owasp_id) or [])
    if check_id == "PIN-DEFINITION-DRIFT":
        atlas = list(PIN_ATLAS)
    return owasp, atlas
