"""Check: AI agent instruction/permission/config files for tampering.

Scans agent-facing config files (AGENTS.md, .bobrules, .bob/*, .cursorrules,
.mcp.json, .github/copilot-instructions.md, ...) for:
  - hidden Unicode (zero-width chars, bidi overrides, Unicode tag chars used
    for ASCII smuggling) with the decoded hidden text shown as evidence
  - suspicious instruction patterns (prompt injection, exfiltration,
    disabling checks, asking the agent to hide actions from the user)
  - base64 blobs that decode to such suspicious text
  - mcp.json servers with over-broad alwaysAllow, unknown remote URLs, or
    plaintext tokens
  - custom_modes.yaml modes that grant broad edit + command/execute access
  - secret-looking files (.env, *.pem, id_rsa) present with no ignore rule
    covering them
"""

from __future__ import annotations

import base64
import fnmatch
import json
import re
from pathlib import Path

from guard.findings import make_finding
from guard.gitutil import file_at_ref, list_files_at_ref

CHECK = "agent_config"

# --- target file matching -------------------------------------------------

_BOB_SUBDIRS = (".bob/rules", ".bob/skills", ".bob/hooks", ".bob/commands")
_EXACT_NAMES = {
    ".bobrules",
    ".cursorrules",
    ".mcp.json",
    ".github/copilot-instructions.md",
    ".bob/custom_modes.yaml",
    ".bob/mcp.json",
}


def is_agent_config_file(path: str) -> bool:
    norm = path.replace("\\", "/")
    if Path(norm).name == "AGENTS.md":
        return True
    if norm in _EXACT_NAMES:
        return True
    for sub in _BOB_SUBDIRS:
        if norm == sub or norm.startswith(sub + "/") or norm.startswith(sub) and norm[len(sub):].startswith((".", "/")):
            return True
    return False


_SECRET_FILE_PATTERNS = (".env", "*.pem", "id_rsa")


def is_secret_looking_file(path: str) -> bool:
    name = Path(path).name
    if name == ".env":
        return True
    if name.endswith(".pem"):
        return True
    if name == "id_rsa":
        return True
    return False


# --- hidden unicode --------------------------------------------------------

_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF}
_BIDI_OVERRIDE = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_TAG_START, _TAG_END = 0xE0000, 0xE007F


def _decode_tag_chars(codepoints: list[int]) -> str:
    chars = []
    for cp in codepoints:
        ascii_code = cp - _TAG_START
        if 0x20 <= ascii_code <= 0x7E:
            chars.append(chr(ascii_code))
    return "".join(chars)


def find_hidden_unicode(content: str) -> list[tuple[int, str, str]]:
    """Returns [(line_no, kind, evidence_text)]."""
    findings = []
    lines = content.splitlines()
    for i, line in enumerate(lines, start=1):
        zero_width_hits = [c for c in line if ord(c) in _ZERO_WIDTH]
        bidi_hits = [c for c in line if ord(c) in _BIDI_OVERRIDE]
        tag_hits = [ord(c) for c in line if _TAG_START <= ord(c) <= _TAG_END]

        if zero_width_hits:
            codepoints = ", ".join(f"U+{ord(c):04X}" for c in zero_width_hits)
            findings.append((i, "zero-width", f"{len(zero_width_hits)} zero-width char(s): {codepoints}"))
        if bidi_hits:
            codepoints = ", ".join(f"U+{ord(c):04X}" for c in bidi_hits)
            findings.append((i, "bidi-override", f"{len(bidi_hits)} bidi override char(s): {codepoints}"))
        if tag_hits:
            decoded = _decode_tag_chars(tag_hits)
            findings.append((i, "unicode-tag", f"decoded hidden text: {decoded!r}" if decoded else f"{len(tag_hits)} unicode tag char(s)"))
    return findings


# --- suspicious instruction text -------------------------------------------

_SUSPICIOUS_PATTERNS: list[tuple[str, str, str]] = [
    (
        r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions",
        "critical",
        "Instructs the agent to ignore previous instructions (prompt injection)",
    ),
    (
        r"ignore\s+(the\s+)?system\s+(prompt|instructions)",
        "critical",
        "Instructs the agent to ignore its system prompt (prompt injection)",
    ),
    (
        r"\b(read|cat|open|print|dump|export|upload|send)\b[^\n]{0,40}\.env\b",
        "critical",
        "Instructs reading or sending the .env file",
    ),
    (
        r"\b(read|cat|open|print|dump|export|send|exfiltrate|upload|post)\b[^\n]{0,40}\b(secrets?|api[_ -]?keys?|apikeys?|credentials?|tokens?|passwords?)\b",
        "critical",
        "Instructs reading or sending secrets/keys/credentials",
    ),
    (
        r"\b(curl|wget|invoke-webrequest|iwr)\b[^\n]{0,80}https?://",
        "high",
        "Instructs fetching an external URL via curl/wget/Invoke-WebRequest",
    ),
    (
        r"\b(disable|skip|bypass|turn off)\b[^\n]{0,30}\b(tests?|checks?|lint(ing)?|ci)\b",
        "high",
        "Instructs disabling tests or checks",
    ),
    (
        r"don'?t\s+tell\s+the\s+user",
        "critical",
        "Instructs the agent to conceal actions from the user",
    ),
    (
        r"without\s+(telling|informing|notifying)\s+the\s+user",
        "critical",
        "Instructs the agent to conceal actions from the user",
    ),
]
_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), sev, desc) for p, sev, desc in _SUSPICIOUS_PATTERNS]


def find_suspicious_instructions(content: str) -> list[tuple[int, str, str, str]]:
    """Returns [(line_no, severity, description, matched_text)]."""
    results = []
    for i, line in enumerate(content.splitlines(), start=1):
        for regex, sev, desc in _COMPILED_PATTERNS:
            m = regex.search(line)
            if m:
                results.append((i, sev, desc, m.group(0)))
    return results


_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def find_suspicious_base64(content: str) -> list[tuple[int, str, str, str]]:
    """Decode base64-looking blobs and re-run the suspicious-pattern scan on them."""
    results = []
    for i, line in enumerate(content.splitlines(), start=1):
        for match in _BASE64_RE.finditer(line):
            blob = match.group(0)
            try:
                decoded_bytes = base64.b64decode(blob, validate=True)
                decoded = decoded_bytes.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if not decoded.isprintable() and not all(c.isprintable() or c in "\r\n\t" for c in decoded):
                continue
            for regex, sev, desc in _COMPILED_PATTERNS:
                m = regex.search(decoded)
                if m:
                    results.append((i, sev, f"Base64 blob decodes to suspicious instruction: {desc}", decoded[:200]))
    return results


# --- mcp.json ---------------------------------------------------------------

_UNSAFE_TOOL_TOKENS = re.compile(
    r"(shell|exec|bash|powershell|pwsh|terminal|run[_ -]?command|write[_ -]?file|delete[_ -]?file)",
    re.IGNORECASE,
)
_PLACEHOLDER_TOKEN = re.compile(r"YOUR_|<.*>|FAKE_|xxx|REPLACE|CHANGEME|\$\{", re.IGNORECASE)
_TOKEN_KEYS = ("token", "apikey", "api_key", "authorization", "secret", "password")


def check_mcp_json(content: str, path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return findings

    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        return findings

    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        always_allow = cfg.get("alwaysAllow")
        if isinstance(always_allow, list):
            for tool in always_allow:
                if isinstance(tool, str) and _UNSAFE_TOOL_TOKENS.search(tool):
                    findings.append(
                        make_finding(
                            check=CHECK,
                            severity="critical",
                            title=f"MCP server '{name}' has alwaysAllow on a shell/exec/write tool",
                            evidence=f'"alwaysAllow": [..., "{tool}", ...]',
                            recommendation=(
                                "Remove shell/exec/write-capable tools from alwaysAllow so they "
                                "require explicit per-call approval."
                            ),
                            file=path,
                        )
                    )

        url = cfg.get("url")
        if isinstance(url, str) and re.match(r"^https?://", url) and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(
                make_finding(
                    check=CHECK,
                    severity="high",
                    title=f"MCP server '{name}' points at an unreviewed remote URL",
                    evidence=f'"url": "{url}"',
                    recommendation="Confirm this remote MCP endpoint is trusted before allowing it.",
                    file=path,
                )
            )

        def _scan_for_tokens(obj, prefix: str) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and k.lower().replace("-", "_") in _TOKEN_KEYS:
                        if v and not _PLACEHOLDER_TOKEN.search(v):
                            findings.append(
                                make_finding(
                                    check=CHECK,
                                    severity="high",
                                    title=f"MCP server '{name}' has a plaintext token/secret in config",
                                    evidence=f'"{k}": "<redacted, len={len(v)}>"',
                                    recommendation="Move secrets to environment variables, never commit them in mcp.json.",
                                    file=path,
                                )
                            )
                    else:
                        _scan_for_tokens(v, prefix + "." + k)
            elif isinstance(obj, list):
                for item in obj:
                    _scan_for_tokens(item, prefix)

        _scan_for_tokens(cfg.get("env", {}), name)

    return findings


# --- custom_modes.yaml (minimal, regex/line-based) --------------------------

_EDIT_TOKEN = re.compile(r"\bedit\b", re.IGNORECASE)
_EXEC_TOKEN = re.compile(r"\b(command|execute|shell|terminal)\b", re.IGNORECASE)
_NAME_LINE = re.compile(r"^\s*(?:-\s*)?(?:name|slug)\s*:\s*(.+?)\s*$")


def check_custom_modes_yaml(content: str, path: str) -> list[dict]:
    findings: list[dict] = []
    lines = content.splitlines()

    blocks: list[tuple[str, list[str], int]] = []  # (name, block_lines, start_line_no)
    current_name = None
    current_lines: list[str] = []
    current_start = 1

    def flush():
        if current_lines:
            blocks.append((current_name or "(unnamed mode)", current_lines, current_start))

    for i, line in enumerate(lines, start=1):
        is_new_item = re.match(r"^-\s*\S", line) is not None
        if is_new_item:
            flush()
            current_lines = [line]
            current_start = i
            m = _NAME_LINE.match(line)
            current_name = m.group(1) if m else None
        else:
            current_lines.append(line)
            if current_name is None:
                m = _NAME_LINE.match(line)
                if m:
                    current_name = m.group(1)
    flush()

    for name, block_lines, start_line in blocks:
        block_text = "\n".join(block_lines)
        if _EDIT_TOKEN.search(block_text) and _EXEC_TOKEN.search(block_text):
            findings.append(
                make_finding(
                    check=CHECK,
                    severity="high",
                    title=f"Custom mode '{name}' grants broad edit + command/execute permissions",
                    evidence=block_text.strip()[:300],
                    recommendation=(
                        "Scope this custom mode down: avoid combining unrestricted file edit "
                        "with shell/command execution in one mode."
                    ),
                    file=path,
                    line=start_line,
                )
            )
    return findings


# --- ignore-file coverage ----------------------------------------------------

def _parse_ignore_lines(content: str) -> list[str]:
    return [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]


def is_covered_by_ignore(path: str, ignore_lines: list[str]) -> bool:
    name = Path(path).name
    for pat in ignore_lines:
        pat_clean = pat.lstrip("/").rstrip("/")
        if pat_clean in (name, path):
            return True
        if fnmatch.fnmatch(name, pat_clean) or fnmatch.fnmatch(path, pat_clean):
            return True
    return False


# --- driver -------------------------------------------------------------

def run(repo: Path, base: str, head: str) -> list[dict]:  # noqa: ARG001 (base kept for CLI symmetry)
    findings: list[dict] = []

    all_paths = list_files_at_ref(repo, head)

    config_paths = [p for p in all_paths if is_agent_config_file(p)]

    for path in config_paths:
        content = file_at_ref(repo, head, path)
        if content is None:
            continue

        for line_no, kind, evidence in find_hidden_unicode(content):
            severity = "critical" if kind == "unicode-tag" else "high"
            findings.append(
                make_finding(
                    check=CHECK,
                    severity=severity,
                    title=f"Hidden Unicode ({kind}) found in {Path(path).name}",
                    evidence=evidence,
                    recommendation="Remove hidden/invisible Unicode characters from agent instruction files.",
                    file=path,
                    line=line_no,
                )
            )

        for line_no, sev, desc, matched in find_suspicious_instructions(content):
            findings.append(
                make_finding(
                    check=CHECK,
                    severity=sev,
                    title=desc,
                    evidence=matched,
                    recommendation="Review and remove this instruction; it should not appear in agent config.",
                    file=path,
                    line=line_no,
                )
            )

        for line_no, sev, desc, decoded in find_suspicious_base64(content):
            findings.append(
                make_finding(
                    check=CHECK,
                    severity=sev,
                    title=desc,
                    evidence=decoded,
                    recommendation="Remove this base64-encoded payload from agent config.",
                    file=path,
                    line=line_no,
                )
            )

        if Path(path).name == "mcp.json":
            findings.extend(check_mcp_json(content, path))

        if Path(path).name == "custom_modes.yaml":
            findings.extend(check_custom_modes_yaml(content, path))

    # secret-looking files present, not covered by .bobignore/.gitignore
    secret_paths = [p for p in all_paths if is_secret_looking_file(p)]
    if secret_paths:
        gitignore = file_at_ref(repo, head, ".gitignore") or ""
        bobignore = file_at_ref(repo, head, ".bobignore") or ""
        ignore_lines = _parse_ignore_lines(gitignore) + _parse_ignore_lines(bobignore)
        for path in secret_paths:
            if not is_covered_by_ignore(path, ignore_lines):
                findings.append(
                    make_finding(
                        check=CHECK,
                        severity="high",
                        title=f"Secret-looking file '{path}' is present and not ignored",
                        evidence=f"'{path}' matches a known secret-file pattern and is not covered by .gitignore/.bobignore",
                        recommendation="Add this file to .gitignore/.bobignore and rotate any credentials it may contain.",
                        file=path,
                    )
                )

    return findings
