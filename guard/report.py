"""Builds report.json and report.md from a list of findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard.findings import SEVERITIES, has_blocking, sort_findings

CHECK_TITLES = {
    "deps": "Dependency Supply-Chain Check",
    "agent_config": "Agent Config / Instruction Tampering Check",
    "tests": "Test Tampering Check",
}


def build_report(
    findings: list[dict[str, Any]],
    repo: str,
    base: str,
    head: str,
) -> dict[str, Any]:
    findings = sort_findings(findings)
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1

    return {
        "tool": "shadowagent-guard",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": repo,
        "base": base,
        "head": head,
        "summary": {
            "total_findings": len(findings),
            "by_severity": counts,
            "blocking": has_blocking(findings),
        },
        "findings": findings,
    }


def write_report_json(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def _severity_badge(severity: str) -> str:
    return {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "⚪ LOW",
    }.get(severity, severity.upper())


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# ShadowAgent Guard Report")
    lines.append("")
    lines.append(f"- **Repo:** `{report['repo']}`")
    lines.append(f"- **Base:** `{report['base']}` -> **Head:** `{report['head']}`")
    lines.append(f"- **Generated:** {report['generated_at']}")
    lines.append(f"- **Blocking (critical/high present):** {'YES' if report['summary']['blocking'] else 'no'}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITIES:
        lines.append(f"| {_severity_badge(sev)} | {report['summary']['by_severity'].get(sev, 0)} |")
    lines.append(f"| **Total** | **{report['summary']['total_findings']}** |")
    lines.append("")

    findings_by_check: dict[str, list[dict]] = {}
    for f in report["findings"]:
        findings_by_check.setdefault(f["check"], []).append(f)

    for check, title in CHECK_TITLES.items():
        findings = findings_by_check.get(check, [])
        lines.append(f"## {title}")
        lines.append("")
        if not findings:
            lines.append("No findings.")
            lines.append("")
            continue
        for f in findings:
            location = f["file"]
            if f.get("line"):
                location += f":{f['line']}"
            lines.append(f"### {_severity_badge(f['severity'])} — {f['title']}")
            lines.append("")
            if location:
                lines.append(f"- **Location:** `{location}`")
            lines.append(f"- **Evidence:** {f['evidence']}")
            lines.append(f"- **Recommendation:** {f['recommendation']}")
            lines.append("")

    return "\n".join(lines)


def write_report_markdown(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.md"
    path.write_text(render_markdown(report), encoding="utf-8")
    return path
