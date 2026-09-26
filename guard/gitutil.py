"""Thin wrappers around `git` for diffing a base ref against a head ref.

Kept deliberately small: everything shells out to the system `git` binary
via subprocess (stdlib only), no third-party git libraries.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def _run(repo: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def changed_files(repo: Path, base: str, head: str) -> list[tuple[str, str]]:
    """Return [(status, path)] for files changed between base and head.

    status is one of A (added), M (modified), D (deleted). Renames are
    reported as their new path with status M for simplicity.
    """
    out = _run(repo, ["diff", "--name-status", f"{base}..{head}"])
    results: list[tuple[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0][0]
        if status == "R" and len(parts) >= 3:
            results.append(("M", parts[2]))
        elif len(parts) >= 2:
            results.append((status, parts[1]))
    return results


def file_at_ref(repo: Path, ref: str, path: str) -> str | None:
    """Return file contents at a given ref, or None if it doesn't exist there."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{ref}:{path}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def unified_diff(repo: Path, base: str, head: str, path: str) -> str:
    return _run(repo, ["diff", "--unified=1", f"{base}..{head}", "--", path])


def diff_line_changes(repo: Path, base: str, head: str, path: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """Parse a unified diff for one file into (added_lines, removed_lines).

    Each entry is (line_number, text). Line numbers are within the head
    file for additions and within the base file for removals.
    """
    diff_text = unified_diff(repo, base, head, path)
    added: list[tuple[int, str]] = []
    removed: list[tuple[int, str]] = []
    old_line = new_line = 0
    for line in diff_text.splitlines():
        if line.startswith("@@"):
            # @@ -old_start,old_len +new_start,new_len @@
            try:
                parts = line.split(" ")
                old_part = parts[1]
                new_part = parts[2]
                old_line = int(old_part.split(",")[0].lstrip("-"))
                new_line = int(new_part.split(",")[0].lstrip("+"))
            except (IndexError, ValueError):
                continue
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-"):
            removed.append((old_line, line[1:]))
            old_line += 1
        else:
            old_line += 1
            new_line += 1
    return added, removed


def list_files_at_ref(repo: Path, ref: str) -> list[str]:
    """List every tracked file path at the given ref."""
    out = _run(repo, ["ls-tree", "-r", "--name-only", ref])
    return [p.strip() for p in out.splitlines() if p.strip()]


def find_files(repo: Path, ref: str, patterns: list[str]) -> list[str]:
    """List paths at `ref` matching any of the given glob-ish suffix patterns."""
    out = _run(repo, ["ls-tree", "-r", "--name-only", ref])
    all_paths = [p for p in out.splitlines() if p.strip()]
    matched = []
    for path in all_paths:
        for pattern in patterns:
            if Path(path).match(pattern) or path == pattern or path.endswith("/" + pattern):
                matched.append(path)
                break
    return matched
