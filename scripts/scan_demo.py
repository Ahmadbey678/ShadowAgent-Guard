"""Scan the demo repo's PR branches, time the ai-pr scan and save the reports.

Usage (PowerShell):
    python scripts\\scan_demo.py C:\\path\\to\\shadowagent-demo-target [--runs 3]

Runs the full `python -m guard scan` (real PyPI/npm lookups) as a subprocess,
so the timing includes interpreter start-up, exactly as CI would see it.
Writes docs/reports/ai-pr.json, docs/reports/ai-pr-remediated.json (+ .md,
.sarif) and docs/reports/timing.json. scripts/build_dashboard.py embeds them.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS = REPO_ROOT / "docs" / "reports"
LABEL = "Ahmadbey678/shadowagent-demo-target"
HEADS = ("ai-pr", "ai-pr-remediated")


def _scan(demo: Path, head: str, out: Path) -> tuple[float, int]:
    cmd = [
        sys.executable, "-m", "guard", "scan",
        "--repo", str(demo), "--base", "main", "--head", head,
        "--repo-label", LABEL, "--out", str(out), "--sarif", str(out / "guard.sarif"),
    ]
    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    elapsed = time.perf_counter() - started
    if not (out / "report.json").is_file():
        raise SystemExit(f"scan of {head} failed:\n{proc.stdout}\n{proc.stderr}")
    return elapsed, proc.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("demo_repo")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args(argv)
    demo = Path(args.demo_repo).resolve()
    REPORTS.mkdir(parents=True, exist_ok=True)

    timings: list[float] = []
    for head in HEADS:
        runs = args.runs if head == "ai-pr" else 1
        for _ in range(runs):
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp)
                elapsed, code = _scan(demo, head, out)
                if head == "ai-pr":
                    timings.append(elapsed)
                for name, dest in (("report.json", f"{head}.json"), ("report.md", f"{head}.md"), ("guard.sarif", f"{head}.sarif")):
                    (REPORTS / dest).write_text((out / name).read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        summary = json.loads((REPORTS / f"{head}.json").read_text(encoding="utf-8"))["summary"]
        print(f"{head}: verdict={summary['verdict']} grade={summary['grade']} findings={summary['total_findings']} exit={code}")

    timing = {
        "branch": "ai-pr",
        "runs": [round(t, 2) for t in timings],
        "average_seconds": round(statistics.mean(timings), 2),
        "includes": "interpreter start-up, git diffing and live PyPI/npm registry lookups",
        "measured_at": time.strftime("%Y-%m-%d"),
    }
    (REPORTS / "timing.json").write_text(json.dumps(timing, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"ai-pr scan time: {timing['runs']} -> average {timing['average_seconds']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
