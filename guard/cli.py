"""Command-line entry point.

    python -m guard scan   --repo <path> --base <ref> --head <ref> --out <dir> [--sarif <path>]
    python -m guard deps   --repo <path> --base <ref> --head <ref> [--out <dir>]
    python -m guard config --repo <path> --base <ref> --head <ref> [--out <dir>]
    python -m guard tests  --repo <path> --base <ref> --head <ref> [--out <dir>]

Common options:
    --fail-on {critical,high,medium,low,none}  severity that makes the exit code 1 (default: high)
    --sarif <path>                              also write SARIF 2.1.0 for GitHub Code Scanning
    --ignore-file <path>                        suppression file to use instead of the base ref's
                                                .shadowagent-ignore

Exit code is 1 if any finding at or above --fail-on is present, 0 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from guard import check_agent_config, check_deps, check_tests
from guard.findings import SEVERITIES
from guard.gitutil import file_at_ref
from guard.report import build_report, write_report_json, write_report_markdown
from guard.sarif import write_sarif
from guard.suppress import IGNORE_FILE, apply_suppressions, parse_ignore_file


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", required=True, help="Path to the git repository to scan")
    p.add_argument("--base", required=True, help="Base git ref (e.g. main)")
    p.add_argument("--head", required=True, help="Head git ref (e.g. a PR branch)")
    p.add_argument("--out", default=None, help="Directory to write report.json/report.md into")
    p.add_argument("--sarif", default=None, help="Also write a SARIF 2.1.0 file to this path")
    p.add_argument(
        "--fail-on",
        default="high",
        choices=[*SEVERITIES, "none"],
        help="Exit 1 when a finding at or above this severity is present (default: high)",
    )
    p.add_argument(
        "--ignore-file",
        default=None,
        help=f"Suppression file (default: {IGNORE_FILE} read from the BASE ref, so a PR can't suppress itself)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m guard", description="ShadowAgent Guard security checks")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run all checks")
    _add_common_args(scan_p)

    deps_p = sub.add_parser("deps", help="Run the dependency supply-chain check only")
    _add_common_args(deps_p)

    config_p = sub.add_parser("config", help="Run the agent-config tampering check only")
    _add_common_args(config_p)

    tests_p = sub.add_parser("tests", help="Run the test-tampering check only")
    _add_common_args(tests_p)

    return parser


def _timeout_from_env() -> float:
    try:
        return float(os.environ.get("GUARD_NETWORK_TIMEOUT", "5"))
    except ValueError:
        return 5.0


def _load_suppressions(repo: Path, base: str, ignore_file: str | None):
    if ignore_file:
        path = Path(ignore_file)
        content = path.read_text(encoding="utf-8") if path.is_file() else ""
    else:
        content = file_at_ref(repo, base, IGNORE_FILE) or ""
    return parse_ignore_file(content)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()

    started = time.perf_counter()
    findings: list[dict] = []
    if args.command in ("scan", "deps"):
        findings.extend(check_deps.run(repo, args.base, args.head, timeout=_timeout_from_env()))
    if args.command in ("scan", "config"):
        findings.extend(check_agent_config.run(repo, args.base, args.head))
    if args.command in ("scan", "tests"):
        findings.extend(check_tests.run(repo, args.base, args.head))

    suppressions, suppression_errors = _load_suppressions(repo, args.base, args.ignore_file)
    active, suppressed = apply_suppressions(findings, suppressions)

    report = build_report(
        active,
        repo=str(repo),
        base=args.base,
        head=args.head,
        suppressed=suppressed,
        suppression_errors=suppression_errors,
        fail_on=args.fail_on,
        duration_seconds=time.perf_counter() - started,
    )

    if args.out:
        out_dir = Path(args.out)
        json_path = write_report_json(report, out_dir)
        md_path = write_report_markdown(report, out_dir)
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
    if args.sarif:
        print(f"Wrote {write_sarif(report, Path(args.sarif))}")
    if not args.out:
        print(json.dumps(report, indent=2))
    else:
        s = report["summary"]
        print(f"Verdict: {s['verdict']}  Grade: {s['grade']}  Findings: {s['total_findings']}  Suppressed: {s['suppressed_count']}")

    return 1 if report["summary"]["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
