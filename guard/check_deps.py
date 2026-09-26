"""Check: newly added dependencies (requirements.txt / package.json).

For every dependency name added between base and head, queries the PyPI
JSON API or the npm registry (metadata only, nothing is ever installed)
and flags:
  - critical: the package does not exist in the registry
  - high:     the package's first release was < 30 days ago
  - high:     the name is an edit distance of 1-2 from a popular package
              (typosquat risk), from a small built-in list
  - medium:   very low download counts, when cheaply available
  - low:      the registry could not be reached ("could not verify")
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard.findings import make_finding
from guard.gitutil import file_at_ref

DEFAULT_TIMEOUT = 5.0
USER_AGENT = "ShadowAgentGuard/0.1 (+https://github.com/)"

POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django",
    "express", "react", "lodash", "axios",
]

NEW_PACKAGE_DAYS_THRESHOLD = 30
LOW_DOWNLOADS_THRESHOLD = 1000  # per-month, applies to whichever registry exposes it cheaply


def levenshtein(a: str, b: str) -> int:
    a, b = a.lower(), b.lower()
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(
                prev[j] + 1,      # deletion
                cur[j - 1] + 1,   # insertion
                prev[j - 1] + cost,  # substitution
            )
        prev = cur
    return prev[-1]


def _normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements_txt(content: str) -> dict[str, str]:
    """Return {normalized_name: raw_name} for a requirements.txt body."""
    deps: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "-e ", "--")):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if not match:
            continue
        name = match.group(1)
        deps[_normalize_pypi_name(name)] = name
    return deps


def parse_package_json(content: str) -> dict[str, str]:
    """Return {name: version_spec} across dependencies + devDependencies."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return {}
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            for name, version in section.items():
                deps[name] = str(version)
    return deps


def _find_line(content: str, needle: str) -> int:
    for i, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return i
    return 0


def _http_get_json(url: str, timeout: float) -> tuple[dict[str, Any] | None, str]:
    """Returns (json_or_None, status) where status is 'ok' | 'not_found' | 'error'."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body), "ok"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, "not_found"
        return None, "error"
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None, "error"


def _pypi_first_release_days_ago(data: dict[str, Any]) -> float | None:
    releases = data.get("releases", {})
    upload_times = []
    for files in releases.values():
        for f in files:
            t = f.get("upload_time_iso_8601")
            if t:
                upload_times.append(t)
    if not upload_times:
        return None
    earliest = min(upload_times)
    try:
        dt = datetime.fromisoformat(earliest.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def _npm_first_release_days_ago(data: dict[str, Any]) -> float | None:
    time_obj = data.get("time", {})
    created = time_obj.get("created")
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def _pypi_downloads_last_month(name: str, timeout: float) -> int | None:
    data, status = _http_get_json(f"https://pypistats.org/api/packages/{name}/recent", timeout)
    if status != "ok" or not data:
        return None
    return data.get("data", {}).get("last_month")


def _npm_downloads_last_month(name: str, timeout: float) -> int | None:
    data, status = _http_get_json(f"https://api.npmjs.org/downloads/point/last-month/{name}", timeout)
    if status != "ok" or not data:
        return None
    return data.get("downloads")


def _typosquat_findings(check: str, name: str, file: str, line: int) -> list[dict]:
    findings = []
    lowered = name.lower()
    for popular in POPULAR_PACKAGES:
        if lowered == popular:
            continue
        dist = levenshtein(lowered, popular)
        if 1 <= dist <= 2:
            findings.append(
                make_finding(
                    check=check,
                    severity="high",
                    title=f"Dependency name '{name}' closely resembles popular package '{popular}'",
                    evidence=f"Levenshtein distance {dist} between '{name}' and '{popular}'",
                    recommendation=(
                        f"Verify '{name}' is the intended package, not a typosquat of '{popular}'. "
                        "Remove or replace it if unintended."
                    ),
                    file=file,
                    line=line,
                )
            )
            break  # one typosquat match is enough
    return findings


def check_pypi_package(name: str, file: str, line: int, timeout: float) -> list[dict]:
    check = "deps"
    findings = _typosquat_findings(check, name, file, line)

    data, status = _http_get_json(f"https://pypi.org/pypi/{name}/json", timeout)
    if status == "not_found":
        findings.append(
            make_finding(
                check=check,
                severity="critical",
                title=f"PyPI package '{name}' does not exist",
                evidence=f"https://pypi.org/pypi/{name}/json returned 404",
                recommendation=(
                    "This package cannot be installed as-is. Confirm the correct package "
                    "name — this may be a hallucinated or since-removed dependency."
                ),
                file=file,
                line=line,
            )
        )
        return findings
    if status == "error" or data is None:
        findings.append(
            make_finding(
                check=check,
                severity="low",
                title=f"Could not verify PyPI package '{name}'",
                evidence="Network error or timeout while querying pypi.org/pypi/<name>/json",
                recommendation="Re-run the scan with network access to verify this dependency.",
                file=file,
                line=line,
            )
        )
        return findings

    age_days = _pypi_first_release_days_ago(data)
    if age_days is not None and age_days < NEW_PACKAGE_DAYS_THRESHOLD:
        findings.append(
            make_finding(
                check=check,
                severity="high",
                title=f"PyPI package '{name}' was first published {age_days} day(s) ago",
                evidence=f"Earliest upload_time_iso_8601 across all releases is {age_days} days old",
                recommendation=(
                    "Newly published packages are a common supply-chain attack vector. "
                    "Confirm this dependency is legitimate and intentionally added."
                ),
                file=file,
                line=line,
            )
        )

    downloads = _pypi_downloads_last_month(name, timeout)
    if downloads is not None and downloads < LOW_DOWNLOADS_THRESHOLD:
        findings.append(
            make_finding(
                check=check,
                severity="medium",
                title=f"PyPI package '{name}' has very low download volume",
                evidence=f"pypistats.org reports {downloads} downloads in the last month",
                recommendation="Low-popularity packages deserve manual review before trusting them.",
                file=file,
                line=line,
            )
        )
    return findings


def check_npm_package(name: str, file: str, line: int, timeout: float) -> list[dict]:
    check = "deps"
    findings = _typosquat_findings(check, name, file, line)

    encoded_name = name.replace("/", "%2f")
    data, status = _http_get_json(f"https://registry.npmjs.org/{encoded_name}", timeout)
    if status == "not_found":
        findings.append(
            make_finding(
                check=check,
                severity="critical",
                title=f"npm package '{name}' does not exist",
                evidence=f"https://registry.npmjs.org/{encoded_name} returned 404",
                recommendation=(
                    "This package cannot be installed as-is. Confirm the correct package "
                    "name — this may be a hallucinated or since-removed dependency."
                ),
                file=file,
                line=line,
            )
        )
        return findings
    if status == "error" or data is None:
        findings.append(
            make_finding(
                check=check,
                severity="low",
                title=f"Could not verify npm package '{name}'",
                evidence="Network error or timeout while querying registry.npmjs.org",
                recommendation="Re-run the scan with network access to verify this dependency.",
                file=file,
                line=line,
            )
        )
        return findings

    age_days = _npm_first_release_days_ago(data)
    if age_days is not None and age_days < NEW_PACKAGE_DAYS_THRESHOLD:
        findings.append(
            make_finding(
                check=check,
                severity="high",
                title=f"npm package '{name}' was first published {age_days} day(s) ago",
                evidence=f"registry 'time.created' is {age_days} days old",
                recommendation=(
                    "Newly published packages are a common supply-chain attack vector. "
                    "Confirm this dependency is legitimate and intentionally added."
                ),
                file=file,
                line=line,
            )
        )

    downloads = _npm_downloads_last_month(name, timeout)
    if downloads is not None and downloads < LOW_DOWNLOADS_THRESHOLD:
        findings.append(
            make_finding(
                check=check,
                severity="medium",
                title=f"npm package '{name}' has very low download volume",
                evidence=f"api.npmjs.org reports {downloads} downloads in the last month",
                recommendation="Low-popularity packages deserve manual review before trusting them.",
                file=file,
                line=line,
            )
        )
    return findings


def run(repo: Path, base: str, head: str, timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
    findings: list[dict] = []

    for path in ("requirements.txt",):
        base_content = file_at_ref(repo, base, path) or ""
        head_content = file_at_ref(repo, head, path)
        if head_content is None:
            continue
        base_deps = parse_requirements_txt(base_content)
        head_deps = parse_requirements_txt(head_content)
        added = {norm: raw for norm, raw in head_deps.items() if norm not in base_deps}
        for norm, raw in sorted(added.items()):
            line = _find_line(head_content, raw)
            findings.extend(check_pypi_package(raw, path, line, timeout))

    for path in ("package.json",):
        base_content = file_at_ref(repo, base, path) or ""
        head_content = file_at_ref(repo, head, path)
        if head_content is None:
            continue
        base_deps = parse_package_json(base_content)
        head_deps = parse_package_json(head_content)
        added = {name: v for name, v in head_deps.items() if name not in base_deps}
        for name in sorted(added):
            line = _find_line(head_content, f'"{name}"')
            findings.extend(check_npm_package(name, path, line, timeout))

    return findings
