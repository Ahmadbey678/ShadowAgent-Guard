import unittest

from guard.findings import make_finding
from guard.report import build_report, render_markdown


class TestReport(unittest.TestCase):
    def test_build_report_counts_and_blocking(self):
        findings = [
            make_finding("deps", "critical", "t1", "e1", "r1", file="a.py"),
            make_finding("tests", "medium", "t2", "e2", "r2", file="b.py"),
        ]
        report = build_report(findings, repo="/tmp/repo", base="main", head="ai-pr")
        self.assertEqual(report["summary"]["total_findings"], 2)
        self.assertEqual(report["summary"]["by_severity"]["critical"], 1)
        self.assertTrue(report["summary"]["blocking"])

    def test_no_blocking_when_only_low_medium(self):
        findings = [make_finding("deps", "low", "t1", "e1", "r1")]
        report = build_report(findings, repo="/tmp/repo", base="main", head="ai-pr")
        self.assertFalse(report["summary"]["blocking"])

    def test_render_markdown_contains_titles(self):
        findings = [make_finding("deps", "high", "Suspicious dep", "ev", "rec", file="requirements.txt")]
        report = build_report(findings, repo="/tmp/repo", base="main", head="ai-pr")
        md = render_markdown(report)
        self.assertIn("Suspicious dep", md)
        self.assertIn("requirements.txt", md)


if __name__ == "__main__":
    unittest.main()
