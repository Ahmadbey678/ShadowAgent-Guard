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
  - custom_modes.yaml/.json modes that grant broad edit + command/execute
    access (an edit group scoped by fileRegex is treated as lower severity
    than an unrestricted one)
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
    ".bob/custom_modes.json",
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


_INVISIBLE = _ZERO_WIDTH | _BIDI_OVERRIDE
_VIEW_LIMIT = 4000


def render_for_humans(content: str) -> str:
    """The text as an editor or PR diff shows it: invisible characters vanish."""
    return "".join(c for c in content if ord(c) not in _INVISIBLE and not _TAG_START <= ord(c) <= _TAG_END)


def decode_for_agent(content: str) -> str:
    """The text as a model tokenizes it: tag characters decoded back to ASCII,
    zero-width/bidi characters made visible as <U+XXXX> markers."""
    out = []
    for c in content:
        cp = ord(c)
        if _TAG_START <= cp <= _TAG_END:
            out.append(chr(cp - _TAG_START) if 0x20 <= cp - _TAG_START <= 0x7E else "")
        elif cp in _INVISIBLE:
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(c)
    return "".join(out)


def hidden_payload(line: str) -> str:
    """Just the decoded tag-character text on one line (empty if none)."""
    return _decode_tag_chars([ord(c) for c in line if _TAG_START <= ord(c) <= _TAG_END])


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


# A negation *directly* before the matched verb ("never print secrets",
# "do not read .env") is almost always a safety rule, not an attack. Only
# direct adjacency counts, so "never forget to send the keys" still fires.
_DIRECT_NEGATION = re.compile(r"\b(never|not|don'?t|doesn'?t|mustn'?t|shouldn'?t|cannot|can'?t|won'?t)\s+$", re.IGNORECASE)


def find_suspicious_instructions(content: str) -> list[tuple[int, str, str, str]]:
    """Returns [(line_no, severity, description, matched_text)].

    Negated matches are kept but downgraded to low, so they stay visible
    without blocking a merge."""
    results = []
    for i, line in enumerate(content.splitlines(), start=1):
        for regex, sev, desc in _COMPILED_PATTERNS:
            m = regex.search(line)
            if not m:
                continue
            if _DIRECT_NEGATION.search(line[: m.start()]) and not m.group(0).lower().startswith("don"):
                results.append((i, "low", f"Negated instruction, likely a safety rule: {desc}", m.group(0)))
            else:
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
                            rule_id="CFG-MCP-ALWAYSALLOW",
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
                    rule_id="CFG-MCP-REMOTE",
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
                                    rule_id="CFG-MCP-SECRET",
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


# --- custom_modes.yaml / custom_modes.json -----------------------------
#
# Real Bob/Roo custom modes nest under a top-level `customModes:` key, one
# indented `- slug: ...` list item per mode, e.g.:
#
#   customModes:
#     - slug: autonomous-fixer
#       name: Autonomous Fixer
#       roleDefinition: >-
#         ...
#       groups:
#         - read
#         - edit
#         - command
#
# `edit` can be *restricted* to a subset of files by pairing it with a
# fileRegex, written as a nested two-item sequence:
#
#       groups:
#         - read
#         - - edit
#           - fileRegex: \.(test|spec)\.(js|ts)$
#             description: Test files only
#         - command
#
# The legacy custom_modes.json equivalent represents that same restriction
# as a two-element list: ["edit", {"fileRegex": "...", "description": "..."}]
#
# We only ever flag the combination of edit + command/execute in one mode;
# an edit group restricted by fileRegex is treated as materially safer than
# an unrestricted one, so it drops the finding from high to low/info.

_EXEC_GROUP_NAMES = {"command", "execute"}


def _mode_permission_finding(
    name: str,
    has_unrestricted_edit: bool,
    has_restricted_edit: bool,
    edit_restriction: str | None,
    has_exec: bool,
    evidence: str,
    path: str,
    line_no: int,
) -> dict | None:
    if not has_exec:
        return None
    if has_unrestricted_edit:
        return make_finding(
            rule_id="CFG-MODE-OVERPERMISSIVE",
            check=CHECK,
            severity="high",
            title=f"Custom mode '{name}' grants broad edit + command/execute permissions",
            evidence=evidence,
            recommendation=(
                "Scope this custom mode down: avoid combining unrestricted file edit "
                "with shell/command execution in one mode."
            ),
            file=path,
            line=line_no,
        )
    if has_restricted_edit:
        return make_finding(
            rule_id="CFG-MODE-OVERPERMISSIVE",
            check=CHECK,
            severity="low",
            title=f"Custom mode '{name}' grants command/execute alongside edit restricted to '{edit_restriction}'",
            evidence=evidence,
            recommendation=(
                "Edit is scoped by fileRegex, which limits blast radius, but confirm "
                "command/execute access is still intentional for this mode."
            ),
            file=path,
            line=line_no,
        )
    return None


# --- YAML (indented list under `customModes:`, or a bare top-level list) ----

_NAME_LINE = re.compile(r"^\s*(?:-\s*)?(?:name|slug)\s*:\s*(.+?)\s*$")
_EDIT_LINE = re.compile(r"^(\s*)-\s*edit\s*$")
_NESTED_EDIT_LINE = re.compile(r"^(\s*)-\s*-\s*edit\s*$")
_EXEC_LINE = re.compile(r"^\s*-\s*(?:command|execute)\s*$")
_FILE_REGEX_LINE = re.compile(r"fileRegex\s*:\s*(.+)$")
_FLOW_GROUPS_LINE = re.compile(r"groups\s*:\s*\[([^\]]*)\]")


def _find_mode_blocks(content: str) -> list[tuple[str, list[str], int]]:
    """Split YAML into (name, block_lines, start_line_no) per mode list item.

    Detects the indent level of `- slug:`/`- name:` list items (0 for a bare
    top-level list, 2+ when nested under `customModes:`) and splits on any
    line at that same indent starting with `-`.
    """
    lines = content.splitlines()

    item_indent: str | None = None
    for line in lines:
        m = re.match(r"^(\s*)-\s*(?:slug|name)\s*:", line)
        if m:
            item_indent = m.group(1)
            break
    if item_indent is None:
        m = re.search(r"^(\s*)-\s*\S", content, re.MULTILINE)
        item_indent = m.group(1) if m else ""

    item_start_re = re.compile(r"^" + re.escape(item_indent) + r"-\s*\S")

    blocks: list[tuple[str, list[str], int]] = []
    current_name: str | None = None
    current_lines: list[str] = []
    current_start = 1

    def flush():
        if current_lines:
            blocks.append((current_name or "(unnamed mode)", current_lines, current_start))

    for i, line in enumerate(lines, start=1):
        if item_start_re.match(line):
            flush()
            current_lines = [line]
            current_start = i
            m = _NAME_LINE.match(line)
            current_name = m.group(1) if m else None
        elif current_lines:
            current_lines.append(line)
            if current_name is None:
                m = _NAME_LINE.match(line)
                if m:
                    current_name = m.group(1)
    flush()
    return blocks


def _scan_yaml_block_permissions(block_lines: list[str]) -> tuple[bool, bool, str | None, bool]:
    """Returns (has_unrestricted_edit, has_restricted_edit, edit_restriction, has_exec)."""
    has_unrestricted_edit = False
    has_restricted_edit = False
    edit_restriction: str | None = None
    has_exec = False

    block_text = "\n".join(block_lines)
    flow_match = _FLOW_GROUPS_LINE.search(block_text)
    if flow_match:
        flow_items = [g.strip() for g in flow_match.group(1).split(",")]
        if "edit" in flow_items:
            has_unrestricted_edit = True
        if any(g in _EXEC_GROUP_NAMES for g in flow_items):
            has_exec = True

    i = 0
    while i < len(block_lines):
        line = block_lines[i]
        nested = _NESTED_EDIT_LINE.match(line)
        if nested:
            base_indent = len(nested.group(1))
            j = i + 1
            found_regex = None
            while j < len(block_lines):
                nxt = block_lines[j]
                stripped = nxt.strip()
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                if stripped.startswith("-") and nxt_indent <= base_indent:
                    break
                m = _FILE_REGEX_LINE.search(nxt)
                if m:
                    found_regex = m.group(1).strip()
                j += 1
            if found_regex:
                has_restricted_edit = True
                edit_restriction = found_regex
            else:
                has_unrestricted_edit = True
            i = j
            continue
        if _EDIT_LINE.match(line):
            has_unrestricted_edit = True
        elif _EXEC_LINE.match(line):
            has_exec = True
        i += 1

    return has_unrestricted_edit, has_restricted_edit, edit_restriction, has_exec


def check_custom_modes_yaml(content: str, path: str) -> list[dict]:
    findings: list[dict] = []
    for name, block_lines, start_line in _find_mode_blocks(content):
        has_unrestricted_edit, has_restricted_edit, edit_restriction, has_exec = _scan_yaml_block_permissions(
            block_lines
        )
        evidence = "\n".join(block_lines).strip()[:300]
        finding = _mode_permission_finding(
            name, has_unrestricted_edit, has_restricted_edit, edit_restriction, has_exec, evidence, path, start_line
        )
        if finding:
            findings.append(finding)
    return findings


# --- JSON (legacy custom_modes.json) ----------------------------------------


def check_custom_modes_json(content: str, path: str) -> list[dict]:
    findings: list[dict] = []
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return findings

    modes = data.get("customModes") if isinstance(data, dict) else None
    if not isinstance(modes, list):
        return findings

    for mode in modes:
        if not isinstance(mode, dict):
            continue
        name = mode.get("slug") or mode.get("name") or "(unnamed mode)"
        groups = mode.get("groups")
        if not isinstance(groups, list):
            continue

        has_unrestricted_edit = False
        has_restricted_edit = False
        edit_restriction: str | None = None
        has_exec = False

        for group in groups:
            if isinstance(group, str):
                group_name, restriction = group, None
            elif isinstance(group, list) and len(group) >= 1:
                group_name = group[0]
                restriction = group[1] if len(group) > 1 and isinstance(group[1], dict) else None
            else:
                continue

            if not isinstance(group_name, str):
                continue
            group_name = group_name.lower()

            if group_name == "edit":
                file_regex = restriction.get("fileRegex") if restriction else None
                if file_regex:
                    has_restricted_edit = True
                    edit_restriction = file_regex
                else:
                    has_unrestricted_edit = True
            elif group_name in _EXEC_GROUP_NAMES:
                has_exec = True

        evidence = json.dumps({"slug": name, "groups": groups})[:300]
        finding = _mode_permission_finding(
            name, has_unrestricted_edit, has_restricted_edit, edit_restriction, has_exec, evidence, path, 0
        )
        if finding:
            findings.append(finding)

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

        content_lines = content.splitlines()
        for line_no, kind, evidence in find_hidden_unicode(content):
            severity = "critical" if kind == "unicode-tag" else "high"
            line_text = content_lines[line_no - 1] if line_no <= len(content_lines) else ""
            findings.append(
                make_finding(
                    rule_id="CFG-HIDDEN-UNICODE",
                    check=CHECK,
                    severity=severity,
                    title=f"Hidden Unicode ({kind}) found in {Path(path).name}",
                    evidence=evidence,
                    recommendation="Remove hidden/invisible Unicode characters from agent instruction files.",
                    file=path,
                    line=line_no,
                    rendered_text=render_for_humans(content)[:_VIEW_LIMIT],
                    decoded_text=decode_for_agent(content)[:_VIEW_LIMIT],
                    hidden_text=hidden_payload(line_text) or decode_for_agent(line_text),
                )
            )

        for line_no, sev, desc, matched in find_suspicious_instructions(content):
            findings.append(
                make_finding(
                    rule_id="CFG-INJECTION",
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
                    rule_id="CFG-ENCODED-INJECTION",
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
        elif Path(path).name == "custom_modes.json":
            findings.extend(check_custom_modes_json(content, path))

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
                        rule_id="CFG-SECRET-UNIGNORED",
                        check=CHECK,
                        severity="high",
                        title=f"Secret-looking file '{path}' is present and not ignored",
                        evidence=f"'{path}' matches a known secret-file pattern and is not covered by .gitignore/.bobignore",
                        recommendation="Add this file to .gitignore/.bobignore and rotate any credentials it may contain.",
                        file=path,
                    )
                )

    return findings
