"""Command-line entry point.

    python -m guard scan   --repo <path> --base <ref> --head <ref> --out <dir>
    python -m guard deps   --repo <path> --base <ref> --head <ref> [--out <dir>]
    python -m guard config --repo <path> --base <ref> --head <ref> [--out <dir>]
    python -m guard tests  --repo <path> --base <ref> --head <ref> [--out <dir>]

Exit code is 1 if any critical/high finding is present, 0 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from guard import check_agent_config, check_deps, check_tests
from guard.findings import has_blocking
from guard.report import build_report, write_report_json, write_report_markdown


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", required=True, help="Path to the git repository to scan")
    p.add_argument("--base", required=True, help="Base git ref (e.g. main)")
    p.add_argument("--head", required=True, help="Head git ref (e.g. a PR branch)")
    p.add_argument("--out", default=None, help="Directory to write report.json/report.md into")


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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()

    findings: list[dict] = []
    if args.command in ("scan", "deps"):
        findings.extend(check_deps.run(repo, args.base, args.head, timeout=_timeout_from_env()))
    if args.command in ("scan", "config"):
        findings.extend(check_agent_config.run(repo, args.base, args.head))
    if args.command in ("scan", "tests"):
        findings.extend(check_tests.run(repo, args.base, args.head))

    report = build_report(findings, repo=str(repo), base=args.base, head=args.head)

    if args.out:
        out_dir = Path(args.out)
        json_path = write_report_json(report, out_dir)
        md_path = write_report_markdown(report, out_dir)
        print(f"Wrote {json_path}")
        print(f"Wrote {md_path}")
    else:
        print(json.dumps(report, indent=2))

    return 1 if has_blocking(findings) else 0


if __name__ == "__main__":
    sys.exit(main())
