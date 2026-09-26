import unittest
from unittest.mock import patch

from guard import check_deps


class TestParsing(unittest.TestCase):
    def test_parse_requirements_txt(self):
        content = "requests==2.31.0\n# comment\n\nnumpy>=1.0\n-r other.txt\nFlask[async]==2.0\n"
        deps = check_deps.parse_requirements_txt(content)
        self.assertIn("requests", deps)
        self.assertIn("numpy", deps)
        self.assertIn("flask", deps)  # normalized
        self.assertNotIn("-r", deps)

    def test_parse_package_json(self):
        content = '{"dependencies": {"react": "^18.0.0"}, "devDependencies": {"eslint": "1.0.0"}}'
        deps = check_deps.parse_package_json(content)
        self.assertEqual(deps["react"], "^18.0.0")
        self.assertEqual(deps["eslint"], "1.0.0")

    def test_parse_package_json_invalid(self):
        self.assertEqual(check_deps.parse_package_json("not json"), {})


class TestLevenshtein(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(check_deps.levenshtein("requests", "requests"), 0)

    def test_one_edit(self):
        self.assertEqual(check_deps.levenshtein("reqeusts", "requests"), 2)
        self.assertEqual(check_deps.levenshtein("requets", "requests"), 1)

    def test_far_apart(self):
        self.assertGreater(check_deps.levenshtein("completely-different", "requests"), 2)


class TestTyposquat(unittest.TestCase):
    def test_flags_close_name(self):
        findings = check_deps._typosquat_findings("deps", "reqeusts", "requirements.txt", 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    def test_does_not_flag_popular_itself(self):
        findings = check_deps._typosquat_findings("deps", "requests", "requirements.txt", 1)
        self.assertEqual(findings, [])

    def test_does_not_flag_unrelated_name(self):
        findings = check_deps._typosquat_findings("deps", "my-totally-unique-internal-lib", "requirements.txt", 1)
        self.assertEqual(findings, [])


class TestPypiCheck(unittest.TestCase):
    @patch("guard.check_deps._http_get_json")
    def test_not_found_is_critical(self, mock_get):
        mock_get.return_value = (None, "not_found")
        findings = check_deps.check_pypi_package("some-hallucinated-pkg", "requirements.txt", 1, timeout=1)
        severities = [f["severity"] for f in findings]
        self.assertIn("critical", severities)

    @patch("guard.check_deps._http_get_json")
    def test_network_error_is_low(self, mock_get):
        mock_get.return_value = (None, "error")
        findings = check_deps.check_pypi_package("requests", "requirements.txt", 1, timeout=1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "low")

    @patch("guard.check_deps._pypi_downloads_last_month", return_value=500000)
    @patch("guard.check_deps._http_get_json")
    def test_recent_release_is_high(self, mock_get, _mock_downloads):
        mock_get.return_value = (
            {
                "releases": {
                    "1.0.0": [{"upload_time_iso_8601": "2099-01-01T00:00:00.000000Z"}],
                }
            },
            "ok",
        )
        with patch("guard.check_deps.datetime") as mock_dt:
            from datetime import datetime, timezone
            mock_dt.now.return_value = datetime(2099, 1, 15, tzinfo=timezone.utc)
            mock_dt.fromisoformat = datetime.fromisoformat
            findings = check_deps.check_pypi_package("some-new-pkg", "requirements.txt", 1, timeout=1)
        severities = [f["severity"] for f in findings]
        self.assertIn("high", severities)


class TestNpmCheck(unittest.TestCase):
    @patch("guard.check_deps._http_get_json")
    def test_not_found_is_critical(self, mock_get):
        mock_get.return_value = (None, "not_found")
        findings = check_deps.check_npm_package("some-hallucinated-pkg", "package.json", 1, timeout=1)
        severities = [f["severity"] for f in findings]
        self.assertIn("critical", severities)


if __name__ == "__main__":
    unittest.main()
