"""Shared finding schema used by every check.

Every finding is a plain dict with this shape:

    {
        "check": str,          # "deps" | "agent_config" | "tests"
        "severity": str,       # "critical" | "high" | "medium" | "low"
        "file": str,           # path relative to the scanned repo, "" if N/A
        "line": int,           # 1-based line number, 0 if N/A
        "title": str,          # short human title
        "evidence": str,       # the concrete snippet/reason that triggered it
        "recommendation": str, # what to do about it
    }
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
) -> dict[str, Any]:
    if severity not in _SEVERITY_RANK:
        raise ValueError(f"invalid severity: {severity!r}")
    return {
        "check": check,
        "severity": severity,
        "file": file,
        "line": line,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, len(SEVERITIES))


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: (severity_rank(f.get("severity", "")), f.get("check", ""), f.get("file", "")))


def has_blocking(findings: list[dict[str, Any]]) -> bool:
    return any(f.get("severity") in ("critical", "high") for f in findings)
