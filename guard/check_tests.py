"""Check: test tampering between base and head.

Flags, based on `git diff base..head`:
  - deleted test files
  - removed test functions/cases (still present in base, gone from head)
  - newly added skip markers (pytest.mark.skip, unittest.skip, it.skip,
    xit, describe.skip, test.todo)
  - weakened assertions (a specific assert/expect replaced by a trivial one)
"""

from __future__ import annotations

import re
from pathlib import Path

from guard.findings import make_finding
from guard.gitutil import changed_files, diff_line_changes

CHECK = "tests"

_PY_TEST_FILE = re.compile(r"^test_.*\.py$|.*_test\.py$")
_JS_TEST_FILE = re.compile(r".*\.(test|spec)\.(js|jsx|ts|tsx)$")


def is_test_file(path: str) -> bool:
    name = Path(path).name
    if _PY_TEST_FILE.match(name):
        return True
    if _JS_TEST_FILE.match(name):
        return True
    parts = Path(path).parts
    if ("test" in parts or "tests" in parts) and Path(path).suffix in (".py", ".js", ".jsx", ".ts", ".tsx"):
        return True
    return False


_PY_DEF_TEST = re.compile(r"^\s*(?:async\s+)?def\s+(test_\w+)\s*\(")
_JS_TEST_CASE = re.compile(r"\b(?:it|test)\s*\(\s*['\"]([^'\"]+)['\"]")

_SKIP_PATTERNS = [
    re.compile(r"@pytest\.mark\.skip"),
    re.compile(r"@unittest\.skip"),
    re.compile(r"\bit\.skip\s*\("),
    re.compile(r"\bxit\s*\("),
    re.compile(r"\bdescribe\.skip\s*\("),
    re.compile(r"\btest\.todo\s*\("),
    re.compile(r"\btest\.skip\s*\("),
]

_ASSERT_STMT = re.compile(r"^\s*(?:self\.)?assert\w*\s*[\s(]")
_SPECIFIC_EXPECT = re.compile(r"\.(toBe|toEqual|toStrictEqual|toContain|toHaveBeenCalled|toMatch)\(")


def _is_specific_assert(text: str) -> bool:
    if not _ASSERT_STMT.search(text):
        return False
    stripped = text.strip().rstrip(";")
    return stripped not in ("assert True", "self.assertTrue(True)")
_TRIVIAL_ASSERT = re.compile(r"^\s*assert\s+True\s*(#.*)?$")
_TRIVIAL_ASSERT_TRUE_CALL = re.compile(r"\bself\.assertTrue\(\s*True\s*\)")
_TRIVIAL_EXPECT = re.compile(r"\.toBeTruthy\(\)")


def _extract_test_name(line: str) -> str | None:
    m = _PY_DEF_TEST.search(line)
    if m:
        return m.group(1)
    m = _JS_TEST_CASE.search(line)
    if m:
        return m.group(1)
    return None


def run(repo: Path, base: str, head: str) -> list[dict]:
    findings: list[dict] = []

    for status, path in changed_files(repo, base, head):
        if not is_test_file(path):
            continue

        if status == "D":
            findings.append(
                make_finding(
                    rule_id="TST-DELETED",
                    check=CHECK,
                    severity="critical",
                    title=f"Test file deleted: {path}",
                    evidence=f"'{path}' existed at {base} and is absent at {head}",
                    recommendation="Confirm this test file's removal was intentional and reviewed.",
                    file=path,
                )
            )
            continue

        if status not in ("M", "A"):
            continue

        added, removed = diff_line_changes(repo, base, head, path)
        added_names = {n for _, text in added if (n := _extract_test_name(text))}

        for line_no, text in removed:
            name = _extract_test_name(text)
            if name and name not in added_names:
                findings.append(
                    make_finding(
                        rule_id="TST-REMOVED",
                        check=CHECK,
                        severity="high",
                        title=f"Test case removed: {name}",
                        evidence=text.strip(),
                        recommendation="Confirm this test was removed intentionally rather than to hide a failure.",
                        file=path,
                        line=line_no,
                    )
                )

        for line_no, text in added:
            for pattern in _SKIP_PATTERNS:
                if pattern.search(text):
                    findings.append(
                        make_finding(
                            rule_id="TST-SKIPPED",
                            check=CHECK,
                            severity="medium",
                            title="Test skip marker added",
                            evidence=text.strip(),
                            recommendation="Confirm this test is meant to be skipped, not silenced to hide a failure.",
                            file=path,
                            line=line_no,
                        )
                    )
                    break

        removed_specific = [
            (ln, t) for ln, t in removed if _is_specific_assert(t) or _SPECIFIC_EXPECT.search(t)
        ]
        for line_no, text in added:
            is_trivial = (
                _TRIVIAL_ASSERT.search(text)
                or _TRIVIAL_ASSERT_TRUE_CALL.search(text)
                or _TRIVIAL_EXPECT.search(text)
            )
            if is_trivial:
                severity = "high" if removed_specific else "medium"
                evidence = text.strip()
                if removed_specific:
                    prior_line, prior_text = removed_specific[0]
                    evidence = f"added: {text.strip()!r} (replacing removed line {prior_line}: {prior_text.strip()!r})"
                findings.append(
                    make_finding(
                        rule_id="TST-WEAKENED",
                        check=CHECK,
                        severity=severity,
                        title="Assertion weakened to a trivial check",
                        evidence=evidence,
                        recommendation="Restore a specific assertion; a trivial always-true check provides no coverage.",
                        file=path,
                        line=line_no,
                    )
                )

    return findings
