"""Shared finding schema used by every check.

Every finding is a plain dict with this shape:

    {
        "rule_id": str,        # stable rule identifier, e.g. "DEP-TYPOSQUAT"
        "check": str,          # "deps" | "agent_config" | "tests"
        "severity": str,       # "critical" | "high" | "medium" | "low"
        "file": str,           # path relative to the scanned repo, "" if N/A
        "line": int,           # 1-based line number, 0 if N/A
        "title": str,          # short human title
        "evidence": str,       # the concrete snippet/reason that triggered it
        "recommendation": str, # what to do about it
    }

Some findings carry extra optional keys (e.g. hidden-Unicode findings add
"rendered_text", "decoded_text" and "hidden_text"). Consumers should ignore
keys they don't know about.
"""

from __future__ import annotations

from typing import Any

SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def make_finding(
    check: str,
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
    file: str = "",
    line: int = 0,
    rule_id: str = "",
    **extra: Any,
) -> dict[str, Any]:
    if severity not in _SEVERITY_RANK:
        raise ValueError(f"invalid severity: {severity!r}")
    finding = {
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "file": file,
        "line": line,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }
    finding.update(extra)
    return finding


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, len(SEVERITIES))


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: (severity_rank(f.get("severity", "")), f.get("check", ""), f.get("file", "")))


def has_blocking(findings: list[dict[str, Any]], fail_on: str = "high") -> bool:
    """True if any finding is at or above the `fail_on` severity ("none" never blocks)."""
    if fail_on == "none":
        return False
    threshold = severity_rank(fail_on)
    return any(severity_rank(f.get("severity", "")) <= threshold for f in findings)


def trust_grade(findings: list[dict[str, Any]]) -> str:
    """A = no findings, B = low only, C = medium max, D = any high, F = any critical."""
    severities = {f.get("severity") for f in findings}
    if "critical" in severities:
        return "F"
    if "high" in severities:
        return "D"
    if "medium" in severities:
        return "C"
    if "low" in severities:
        return "B"
    return "A"


# Stable rule catalogue: rule_id -> (check, short name, description).
RULES: dict[str, tuple[str, str, str]] = {
    "DEP-NONEXISTENT": ("deps", "Nonexistent dependency", "An added dependency does not exist in its registry (hallucinated or removed package; slopsquatting target)."),
    "DEP-TYPOSQUAT": ("deps", "Possible typosquat", "An added dependency name is within edit distance 1-2 of a popular package."),
    "DEP-NEW": ("deps", "Newly published dependency", "An added dependency was first published less than 30 days ago."),
    "DEP-LOW-DOWNLOADS": ("deps", "Low-adoption dependency", "An added dependency has very low monthly download volume."),
    "DEP-UNVERIFIED": ("deps", "Unverified dependency", "The registry could not be reached to verify an added dependency."),
    "DEP-INSTALL-SCRIPT": ("deps", "Install script added or changed", "A package.json preinstall/install/postinstall script was added or changed; it runs automatically on npm install."),
    "CFG-HIDDEN-UNICODE": ("agent_config", "Hidden Unicode in agent config", "Invisible Unicode (tag characters, zero-width, bidi overrides) in an agent instruction file can smuggle instructions humans cannot see."),
    "CFG-INJECTION": ("agent_config", "Prompt injection in agent config", "Agent instruction text tells the agent to ignore instructions, exfiltrate secrets, disable checks or hide actions."),
    "CFG-ENCODED-INJECTION": ("agent_config", "Encoded prompt injection", "A base64 blob in agent config decodes to a prompt-injection instruction."),
    "CFG-MCP-ALWAYSALLOW": ("agent_config", "MCP tool always allowed", "An MCP server auto-approves a shell/exec/write-capable tool."),
    "CFG-MCP-REMOTE": ("agent_config", "Unreviewed remote MCP server", "An MCP server points at a remote URL that has not been reviewed."),
    "CFG-MCP-SECRET": ("agent_config", "Plaintext secret in MCP config", "An MCP server config contains a plaintext token or secret."),
    "CFG-MODE-OVERPERMISSIVE": ("agent_config", "Over-permissive agent mode", "A custom agent mode combines file edit with command/execute access."),
    "CFG-SECRET-UNIGNORED": ("agent_config", "Secret file not ignored", "A secret-looking file is present and not covered by .gitignore/.bobignore."),
    "TST-DELETED": ("tests", "Test file deleted", "A test file present at base was deleted."),
    "TST-REMOVED": ("tests", "Test case removed", "A test function/case present at base was removed."),
    "TST-SKIPPED": ("tests", "Test skip marker added", "A skip/todo marker was added to a test."),
    "TST-WEAKENED": ("tests", "Assertion weakened", "A specific assertion was replaced by a trivial always-true check."),
}
