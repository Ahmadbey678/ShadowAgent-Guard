"""SARIF 2.1.0 output, for GitHub Code Scanning (github/codeql-action/upload-sarif)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from guard import __version__
from guard.findings import RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/Ahmadbey678/ShadowAgent-Guard"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# GitHub maps security-severity to critical (>=9.0), high (7.0-8.9), medium (4.0-6.9), low (<4.0).
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def _rule_descriptor(rule_id: str) -> dict[str, Any]:
    check, name, description = RULES.get(rule_id, ("", rule_id, rule_id))
    return {
        "id": rule_id,
        "name": "".join(part.capitalize() for part in rule_id.split("-")),
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "helpUri": f"{INFORMATION_URI}#rules",
        "properties": {"tags": ["security", "ai-supply-chain", check] if check else ["security"]},
    }


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    severity = finding.get("severity", "low")
    rule_id = finding.get("rule_id") or "UNKNOWN"
    message = f"[{severity.upper()}] {finding.get('title', '')}\nEvidence: {finding.get('evidence', '')}\nFix: {finding.get('recommendation', '')}"
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVEL.get(severity, "note"),
        "message": {"text": message},
        "properties": {"security-severity": _SECURITY_SEVERITY.get(severity, "3.0"), "severity": severity},
    }
    file = finding.get("file", "")
    if file:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file.replace("\\", "/")},
                    "region": {"startLine": max(1, int(finding.get("line") or 1))},
                }
            }
        ]
    fingerprint_src = "|".join([rule_id, file, finding.get("title", "")])
    result["partialFingerprints"] = {"shadowagentGuard/v1": hashlib.sha256(fingerprint_src.encode("utf-8")).hexdigest()}
    if "suppression" in finding:
        result["suppressions"] = [{"kind": "external", "justification": finding["suppression"].get("reason", "")}]
    return result


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", []) + report.get("suppressed", [])
    rule_ids = sorted({f.get("rule_id") or "UNKNOWN" for f in findings})
    rule_index = {rid: i for i, rid in enumerate(rule_ids)}
    results = []
    for f in findings:
        r = _result(f)
        r["ruleIndex"] = rule_index[r["ruleId"]]
        results.append(r)
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShadowAgent Guard",
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule_descriptor(rid) for rid in rule_ids],
                    }
                },
                "automationDetails": {"id": "shadowagent-guard/"},
                "properties": {
                    "verdict": report.get("summary", {}).get("verdict"),
                    "grade": report.get("summary", {}).get("grade"),
                },
                "results": results,
            }
        ],
    }


def write_sarif(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_sarif(report), indent=2), encoding="utf-8")
    return path
