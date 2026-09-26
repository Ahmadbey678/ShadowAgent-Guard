"""End-to-end: build the demo repo and check every planted issue is caught
and the remediated branch passes. Registry lookups are mocked (offline)."""

import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from fixtures.ai_pr_fixture import PLANTED_ISSUES
from guard import check_agent_config, check_deps, check_tests
from guard.findings import has_blocking, trust_grade
from scripts.build_demo import build_demo

PLANTED = [(p["rule_id"], p["file"]) for p in PLANTED_ISSUES]


def _registry(url, timeout):
    if "requests" in url and "reqeusts" not in url:
        return {"releases": {}, "time": {}}, "ok"
    return None, "not_found"


def _scan(repo, head):
    with patch("guard.check_deps._http_get_json", side_effect=_registry):
        findings = check_deps.run(repo, "main", head, timeout=1)
    return findings + check_agent_config.run(repo, "main", head) + check_tests.run(repo, "main", head)


class TestDemoBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.repo = Path(cls._tmp.name) / "demo"
        with redirect_stdout(io.StringIO()):
            build_demo(cls.repo)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_branches(self):
        out = subprocess.run(
            ["git", "-C", str(self.repo), "branch", "--format=%(refname:short)"], capture_output=True, text=True
        ).stdout.split()
        self.assertEqual(sorted(out), ["ai-pr", "ai-pr-remediated", "main"])

    def test_every_planted_issue_detected(self):
        findings = _scan(self.repo, "ai-pr")
        caught = {(f["rule_id"], f["file"]) for f in findings}
        for planted in PLANTED:
            self.assertIn(planted, caught)
        self.assertEqual(trust_grade(findings), "F")
        self.assertTrue(has_blocking(findings))

    def test_remediated_branch_passes(self):
        findings = _scan(self.repo, "ai-pr-remediated")
        self.assertFalse(has_blocking(findings), findings)
        self.assertIn(trust_grade(findings), ("A", "B"))

    def test_refuses_inside_repo(self):
        with self.assertRaises(SystemExit):
            build_demo(Path(__file__).resolve().parent / "_nope")


if __name__ == "__main__":
    unittest.main()
