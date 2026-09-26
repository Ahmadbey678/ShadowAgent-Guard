"""Build a separate demo git repository for exercising ShadowAgent Guard.

Usage (PowerShell):
    python scripts\\build_demo.py C:\\path\\to\\some\\empty-or-new-dir

Creates <target_dir> as a fresh git repo with:
  - `main`: a small, clean Python calculator app with a healthy test suite
  - `ai-pr`: a branch simulating an AI coding agent's pull request that
    plants ~9 supply-chain / prompt-injection / test-tampering issues

Refuses to run if <target_dir> is inside this repository, since the demo
repo is meant to be scanned by ShadowAgent Guard from the outside.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from fixtures.ai_pr_fixture import (  # noqa: E402
    DELETED_FILES,
    NEW_OR_MODIFIED_FILES,
    REQUIREMENTS_ADDITIONS,
)
from fixtures.base_app_fixture import FILES as BASE_FILES  # noqa: E402


def _run_git(repo: Path, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed:\n{proc.stderr}")


def _write_files(root: Path, files: dict[str, str]) -> None:
    for rel_path, content in files.items():
        full = root / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")


def build_demo(target_dir: Path) -> None:
    target_dir = target_dir.resolve()

    try:
        target_dir.relative_to(REPO_ROOT)
        is_inside = True
    except ValueError:
        is_inside = False
    if is_inside:
        raise SystemExit(
            f"Refusing to build the demo repo inside this repository ({REPO_ROOT}). "
            "Pick a target directory outside of it."
        )

    if target_dir.exists() and any(target_dir.iterdir()):
        raise SystemExit(f"Target directory '{target_dir}' already exists and is not empty.")

    target_dir.mkdir(parents=True, exist_ok=True)

    _run_git(target_dir, "init", "-q", "-b", "main")
    _run_git(target_dir, "config", "user.email", "demo@shadowagent-guard.local")
    _run_git(target_dir, "config", "user.name", "ShadowAgent Guard Demo Builder")

    _write_files(target_dir, BASE_FILES)
    _run_git(target_dir, "add", "-A")
    _run_git(target_dir, "commit", "-q", "-m", "Initial clean app + tests")

    _run_git(target_dir, "checkout", "-q", "-b", "ai-pr")

    requirements_path = target_dir / "requirements.txt"
    requirements_path.write_text(
        requirements_path.read_text(encoding="utf-8") + REQUIREMENTS_ADDITIONS, encoding="utf-8"
    )

    _write_files(target_dir, NEW_OR_MODIFIED_FILES)

    for rel_path in DELETED_FILES:
        path = target_dir / rel_path
        if path.exists():
            path.unlink()

    _run_git(target_dir, "add", "-A")
    _run_git(
        target_dir,
        "commit",
        "-q",
        "-m",
        "AI agent PR: add retry dependency + agent config + tweak tests",
    )

    print(f"Demo repo created at: {target_dir}")
    print("Branches: main (clean base), ai-pr (planted issues)")
    print(
        "Scan it with:\n"
        f'  python -m guard scan --repo "{target_dir}" --base main --head ai-pr --out "{target_dir / "_scan_out"}"'
    )


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("Usage: python scripts/build_demo.py <target_dir>", file=sys.stderr)
        return 2
    build_demo(Path(argv[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
