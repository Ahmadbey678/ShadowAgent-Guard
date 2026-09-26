"""Shared helpers for building small throwaway git repos in tests."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    return repo


def write_files(repo: Path, files: dict[str, str]) -> None:
    for rel_path, content in files.items():
        full = repo / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")


def commit_all(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def new_branch(repo: Path, name: str) -> None:
    _git(repo, "checkout", "-q", "-b", name)


class TempRepo:
    """Context manager giving a real git repo with a base commit on main."""

    def __init__(self):
        self._tmpdir = tempfile.TemporaryDirectory()

    def __enter__(self) -> Path:
        self.path = init_repo(Path(self._tmpdir.name))
        return self.path

    def __exit__(self, *exc):
        self._tmpdir.cleanup()
