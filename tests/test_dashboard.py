"""The published dashboard (docs/index.html) parses and its embedded data loads."""

import json
import unittest
from html.parser import HTMLParser
from pathlib import Path

from scripts.build_dashboard import embed

PAGE = Path(__file__).resolve().parent.parent / "docs" / "index.html"


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.data_block, self.scripts_src, self.links = [], None, [], []
        self._in_data = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("id") == "sag-data":
            self._in_data, self.data_block = True, ""
        if tag == "script" and a.get("src"):
            self.scripts_src.append(a["src"])
        if tag == "link" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_data = False

    def handle_data(self, data):
        if self._in_data:
            self.data_block += data


class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = PAGE.read_text(encoding="utf-8")
        cls.parser = _Collector()
        cls.parser.feed(cls.html)

    def test_self_contained(self):
        self.assertEqual(self.parser.scripts_src, [])
        self.assertEqual(self.parser.links, [])
        self.assertNotIn("http://", self.html.replace("http://www.w3.org/2000/svg", ""))

    def test_embedded_real_reports(self):
        data = json.loads(self.parser.data_block)
        before, after = data["reports"]["ai-pr"], data["reports"]["ai-pr-remediated"]
        self.assertEqual(before["tool"], "shadowagent-guard")
        self.assertEqual(before["summary"]["verdict"], "BLOCK")
        self.assertEqual(before["summary"]["grade"], "F")
        self.assertGreaterEqual(before["summary"]["total_findings"], 12)
        self.assertEqual(after["summary"]["verdict"], "PASS")
        self.assertIn(after["summary"]["grade"], ("A", "B"))
        self.assertTrue(all(row["caught"] for row in data["detection"]))
        self.assertTrue(any(f.get("hidden_text") for f in before["findings"]))
        self.assertGreater(data["timing"]["average_seconds"], 0)
        self.assertEqual(len(data["hardening"]), 5)

    def test_embed_escapes_script_breakout(self):
        page = '<script id="sag-data" type="application/json">{}</script>'
        out = embed({"x": "</script><script>alert(1)</script>"}, page)
        self.assertEqual(out.count("</script>"), 1)
        self.assertEqual(json.loads(out[len('<script id="sag-data" type="application/json">'):-len("</script>")])["x"],
                         "</script><script>alert(1)</script>")


if __name__ == "__main__":
    unittest.main()
