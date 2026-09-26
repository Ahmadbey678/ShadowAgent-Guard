"""Embed real scan data into docs/index.html (the GitHub Pages dashboard).

Usage (PowerShell):
    python scripts\\scan_demo.py C:\\path\\to\\shadowagent-demo-target   # produce docs/reports/*
    python scripts\\build_dashboard.py                                   # embed them

docs/index.html is the single source for the page. This script only
replaces the contents of its <script id="sag-data" type="application/json">
block with: the ai-pr and ai-pr-remediated reports (never hand-written), the
measured scan time, the detection table (computed from the ai-pr report),
and the risky-vs-hardened file pairs from fixtures/.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fixtures.ai_pr_fixture import NEW_OR_MODIFIED_FILES, PLANTED_ISSUES  # noqa: E402
from fixtures.remediation_fixture import HARDENED_FILES, HARDENING_NOTES  # noqa: E402
from guard import __version__  # noqa: E402
from guard.check_agent_config import decode_for_agent, hidden_payload  # noqa: E402

PAGE = REPO_ROOT / "docs" / "index.html"
REPORTS = REPO_ROOT / "docs" / "reports"
DATA_BLOCK = re.compile(r'(<script id="sag-data" type="application/json">)(.*?)(</script>)', re.DOTALL)

REPO_URL = "https://github.com/Ahmadbey678/ShadowAgent-Guard"
DEMO_URL = "https://github.com/Ahmadbey678/shadowagent-demo-target"
LINKS = {
    "repo": REPO_URL,
    "demo": DEMO_URL,
    "pr_blocked": f"{DEMO_URL}/pull/1",
    "pr_remediated": f"{DEMO_URL}/pull/2",
    "dashboard": "https://ahmadbey678.github.io/ShadowAgent-Guard/",
}
HARDENING_ORDER = ["AGENTS.md", ".bob/rules/rules.md", ".bob/mcp.json", ".bob/custom_modes.yaml", ".bobignore"]


def _hardening() -> list[dict[str, str]]:
    entries = []
    for path in HARDENING_ORDER:
        risky = NEW_OR_MODIFIED_FILES.get(path, "")
        hidden = "".join(hidden_payload(line) for line in risky.splitlines())
        entries.append(
            {
                "file": path,
                "risky": decode_for_agent(risky),
                "hidden": hidden,
                "hardened": HARDENED_FILES[path],
                **HARDENING_NOTES[path],
            }
        )
    return entries


def _detection(report: dict) -> list[dict]:
    rows = []
    for planted in PLANTED_ISSUES:
        match = next(
            (f for f in report["findings"] if f.get("rule_id") == planted["rule_id"] and f.get("file") == planted["file"]),
            None,
        )
        rows.append({**planted, "caught": match is not None, "severity": match["severity"] if match else ""})
    return rows


def build_data() -> dict:
    reports = {name: json.loads((REPORTS / f"{name}.json").read_text(encoding="utf-8")) for name in ("ai-pr", "ai-pr-remediated")}
    return {
        "version": __version__,
        "links": LINKS,
        "labels": {"ai-pr": "ai-pr (before)", "ai-pr-remediated": "remediated (after)"},
        "reports": reports,
        "timing": json.loads((REPORTS / "timing.json").read_text(encoding="utf-8")),
        "detection": _detection(reports["ai-pr"]),
        "hardening": _hardening(),
    }


def embed(data: dict, html: str) -> str:
    payload = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
    # Safe inside <script>: no "</script>", no "<!--", no HTML-significant chars.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    if not DATA_BLOCK.search(html):
        raise SystemExit("docs/index.html has no sag-data block")
    return DATA_BLOCK.sub(lambda m: m.group(1) + payload + m.group(3), html, count=1)


def main() -> int:
    data = build_data()
    html = PAGE.read_text(encoding="utf-8")
    PAGE.write_text(embed(data, html), encoding="utf-8", newline="\n")
    caught = sum(r["caught"] for r in data["detection"])
    print(f"Embedded {len(data['reports'])} reports, {len(data['hardening'])} hardened files, detection {caught}/{len(data['detection'])} into {PAGE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
