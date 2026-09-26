"""`.shadowagent-ignore`: explicit, reasoned suppressions.

File format, one suppression per line:

    # rule_id      [file glob]          -- reason (mandatory)
    DEP-NEW        requirements.txt     -- internal-lib is ours, published last week, vetted by secteam
    TST-SKIPPED    tests/test_slow.py   -- nightly-only suite, tracked in #123
    CFG-MODE-OVERPERMISSIVE             -- release mode is intentionally allowed to run commands

- `rule_id` may use fnmatch wildcards (e.g. `DEP-*`).
- The file glob is optional; when omitted the rule is suppressed everywhere.
- The reason after ` -- ` is mandatory. Lines without one are rejected and
  reported in the report's `suppression_errors`, never silently applied.

Suppressed findings are moved to the report's `suppressed` list with the
matching reason attached. They are never dropped.

Security: the CLI reads this file from the *base* ref, not the head ref, so
a pull request cannot suppress its own findings by adding an ignore entry.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

IGNORE_FILE = ".shadowagent-ignore"


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    file_glob: str
    reason: str
    line: int

    def matches(self, finding: dict[str, Any]) -> bool:
        if not fnmatch.fnmatchcase(finding.get("rule_id", ""), self.rule_id):
            return False
        if not self.file_glob:
            return True
        path = finding.get("file", "").replace("\\", "/")
        return fnmatch.fnmatchcase(path, self.file_glob)


def parse_ignore_file(content: str) -> tuple[list[Suppression], list[str]]:
    """Returns (suppressions, errors)."""
    suppressions: list[Suppression] = []
    errors: list[str] = []
    for line_no, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        spec, sep, reason = line.partition(" -- ")
        reason = reason.strip()
        if not sep or not reason:
            errors.append(f"{IGNORE_FILE}:{line_no}: missing mandatory ' -- reason'; entry ignored: {line[:120]}")
            continue
        tokens = spec.split()
        if not tokens or len(tokens) > 2:
            errors.append(f"{IGNORE_FILE}:{line_no}: expected '<rule_id> [file-glob] -- reason'; entry ignored")
            continue
        suppressions.append(
            Suppression(
                rule_id=tokens[0],
                file_glob=tokens[1] if len(tokens) == 2 else "",
                reason=reason,
                line=line_no,
            )
        )
    return suppressions, errors


def apply_suppressions(
    findings: list[dict[str, Any]], suppressions: list[Suppression]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into (active, suppressed). Suppressed findings get a
    `suppression` key describing the entry that matched."""
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        match = next((s for s in suppressions if s.matches(finding)), None)
        if match is None:
            active.append(finding)
            continue
        suppressed.append(
            {
                **finding,
                "suppression": {
                    "rule_id": match.rule_id,
                    "file_glob": match.file_glob,
                    "reason": match.reason,
                    "source": f"{IGNORE_FILE}:{match.line}",
                },
            }
        )
    return active, suppressed
