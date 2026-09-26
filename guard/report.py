"""Builds report.json and report.md from a list of findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard import __version__
from guard.findings import SEVERITIES, has_blocking, sort_findings, trust_grade

CHECK_TITLES = {
    "deps": "Dependency Supply-Chain Check",
    "agent_config": "Agent Config / Instruction Tampering Check",
    "tests": "Test Tampering Check",
}

GRADE_MEANING = {
    "A": "no findings",
    "B": "low-severity findings only",
    "C": "medium-severity findings at most",
    "D": "high-severity findings present",
    "F": "critical findings present",
}


def build_report(
    findings: list[dict[str, Any]],
    repo: str,
    base: str,
    head: str,
    suppressed: list[dict[str, Any]] | None = None,
    suppression_errors: list[str] | None = None,
    fail_on: str = "high",
    duration_seconds: float | None = None,
) -> dict[str, Any]:
    findings = sort_findings(findings)
    suppressed = sort_findings(suppressed or [])
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1

    blocking = has_blocking(findings, fail_on)
    report: dict[str, Any] = {
        "tool": "shadowagent-guard",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": repo,
        "base": base,
        "head": head,
        "summary": {
            "total_findings": len(findings),
            "by_severity": counts,
            "blocking": blocking,
            "verdict": "BLOCK" if blocking else "PASS",
            "grade": trust_grade(findings),
            "fail_on": fail_on,
            "suppressed_count": len(suppressed),
        },
        "findings": findings,
        "suppressed": suppressed,
        "suppression_errors": list(suppression_errors or []),
    }
    if duration_seconds is not None:
        report["summary"]["duration_seconds"] = round(duration_seconds, 2)
    return report


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


def _fence(text: str) -> list[str]:
    body = text.replace("```", "'''")
    return ["```text", body, "```"]


def _render_finding(f: dict[str, Any], lines: list[str]) -> None:
    location = f.get("file", "")
    if f.get("line"):
        location += f":{f['line']}"
    rule = f" `{f['rule_id']}`" if f.get("rule_id") else ""
    lines.append(f"### {_severity_badge(f['severity'])}{rule} — {f['title']}")
    lines.append("")
    if location:
        lines.append(f"- **Location:** `{location}`")
    lines.append(f"- **Evidence:** {f['evidence']}")
    lines.append(f"- **Recommendation:** {f['recommendation']}")
    if "suppression" in f:
        s = f["suppression"]
        lines.append(f"- **Suppressed by** `{s['source']}`: {s['reason']}")
    lines.append("")
    if f.get("hidden_text"):
        lines.append("<details><summary>What humans see vs. what the agent sees</summary>")
        lines.append("")
        lines.append("**As rendered to humans:**")
        lines.append("")
        lines.extend(_fence(f.get("rendered_text", "")))
        lines.append("")
        lines.append("**Decoded, as seen by the agent:**")
        lines.append("")
        lines.extend(_fence(f.get("decoded_text", "")))
        lines.append("")
        lines.append("</details>")
        lines.append("")


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    verdict = summary.get("verdict", "BLOCK" if summary.get("blocking") else "PASS")
    grade = summary.get("grade", "")
    lines: list[str] = []
    lines.append("# ShadowAgent Guard Report")
    lines.append("")
    icon = "⛔" if verdict == "BLOCK" else "✅"
    lines.append(f"## {icon} Verdict: **{verdict}** · Trust grade **{grade}** ({GRADE_MEANING.get(grade, '')})")
    lines.append("")
    lines.append(f"- **Repo:** `{report['repo']}`")
    lines.append(f"- **Base:** `{report['base']}` -> **Head:** `{report['head']}`")
    lines.append(f"- **Generated:** {report['generated_at']}")
    lines.append(f"- **Fails on:** {summary.get('fail_on', 'high')} and above")
    lines.append(f"- **Blocking:** {'YES' if summary['blocking'] else 'no'}")
    if "duration_seconds" in summary:
        lines.append(f"- **Scan time:** {summary['duration_seconds']}s")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITIES:
        lines.append(f"| {_severity_badge(sev)} | {summary['by_severity'].get(sev, 0)} |")
    lines.append(f"| **Total** | **{summary['total_findings']}** |")
    if summary.get("suppressed_count"):
        lines.append(f"| Suppressed (not counted) | {summary['suppressed_count']} |")
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
            _render_finding(f, lines)

    suppressed = report.get("suppressed", [])
    if suppressed:
        lines.append("## Suppressed findings")
        lines.append("")
        lines.append("These matched an entry in `.shadowagent-ignore` (read from the base ref) and do not affect the verdict.")
        lines.append("")
        for f in suppressed:
            _render_finding(f, lines)

    errors = report.get("suppression_errors", [])
    if errors:
        lines.append("## Rejected suppression entries")
        lines.append("")
        for e in errors:
            lines.append(f"- {e}")
        lines.append("")

    return "\n".join(lines)


def write_report_markdown(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.md"
    path.write_text(render_markdown(report), encoding="utf-8")
    return path
