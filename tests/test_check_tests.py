import unittest

from guard import check_tests
from tests.helpers import TempRepo, commit_all, write_files


class TestIsTestFile(unittest.TestCase):
    def test_python_patterns(self):
        self.assertTrue(check_tests.is_test_file("tests/test_foo.py"))
        self.assertTrue(check_tests.is_test_file("foo_test.py"))
        self.assertFalse(check_tests.is_test_file("foo.py"))

    def test_js_patterns(self):
        self.assertTrue(check_tests.is_test_file("src/foo.test.js"))
        self.assertTrue(check_tests.is_test_file("src/foo.spec.ts"))
        self.assertFalse(check_tests.is_test_file("src/foo.js"))


class TestRunIntegration(unittest.TestCase):
    def test_deleted_test_file(self):
        with TempRepo() as repo:
            write_files(repo, {"tests/test_math.py": "def test_add():\n    assert 1 + 1 == 2\n"})
            commit_all(repo, "base")
            (repo / "tests" / "test_math.py").unlink()
            commit_all(repo, "delete test")

            findings = check_tests.run(repo, "HEAD~1", "HEAD")
            self.assertTrue(any(f["severity"] == "critical" and "deleted" in f["title"] for f in findings))

    def test_removed_test_function(self):
        with TempRepo() as repo:
            write_files(
                repo,
                {
                    "tests/test_math.py": (
                        "def test_add():\n    assert 1 + 1 == 2\n\n"
                        "def test_sub():\n    assert 2 - 1 == 1\n"
                    )
                },
            )
            commit_all(repo, "base")
            write_files(repo, {"tests/test_math.py": "def test_add():\n    assert 1 + 1 == 2\n"})
            commit_all(repo, "remove test_sub")

            findings = check_tests.run(repo, "HEAD~1", "HEAD")
            self.assertTrue(any("test_sub" in f["title"] for f in findings))

    def test_added_skip_marker(self):
        with TempRepo() as repo:
            write_files(repo, {"tests/test_math.py": "def test_add():\n    assert 1 + 1 == 2\n"})
            commit_all(repo, "base")
            write_files(
                repo,
                {
                    "tests/test_math.py": (
                        "import pytest\n\n@pytest.mark.skip(reason='flaky')\n"
                        "def test_add():\n    assert 1 + 1 == 2\n"
                    )
                },
            )
            commit_all(repo, "skip test")

            findings = check_tests.run(repo, "HEAD~1", "HEAD")
            self.assertTrue(any("skip marker" in f["title"] for f in findings))

    def test_weakened_assertion(self):
        with TempRepo() as repo:
            write_files(repo, {"tests/test_math.py": "def test_add():\n    assert 1 + 1 == 2\n"})
            commit_all(repo, "base")
            write_files(repo, {"tests/test_math.py": "def test_add():\n    assert True\n"})
            commit_all(repo, "weaken test")

            findings = check_tests.run(repo, "HEAD~1", "HEAD")
            self.assertTrue(any("weakened" in f["title"].lower() for f in findings))
            weak = [f for f in findings if "weakened" in f["title"].lower()][0]
            self.assertEqual(weak["severity"], "high")

    def test_no_findings_for_healthy_change(self):
        with TempRepo() as repo:
            write_files(repo, {"tests/test_math.py": "def test_add():\n    assert 1 + 1 == 2\n"})
            commit_all(repo, "base")
            write_files(
                repo,
                {
                    "tests/test_math.py": (
                        "def test_add():\n    assert 1 + 1 == 2\n\n"
                        "def test_mul():\n    assert 2 * 2 == 4\n"
                    )
                },
            )
            commit_all(repo, "add a test")

            findings = check_tests.run(repo, "HEAD~1", "HEAD")
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
