#!/usr/bin/env python3
"""Repository consistency checks for documentation and lab material.

Runs on every pull request. Deterministic and dependency-free.

Checks:
  links       Every relative Markdown link resolves to a file, and every
              #anchor resolves to a heading in the target document.
  identifiers Published docs and labs contain no environment identifiers:
              GUIDs (tenant or subscription IDs), *.onmicrosoft.com tenant
              domains, or IPv4 addresses outside an allowlist of loopback,
              documentation and published provider ranges.
  findings    Any "Appendix: findings" table is numbered 1..N with no gaps.

Known-safe values (for example, an illustrative trace ID in a schema sample)
are listed with a reason in scripts/consistency_allowlist.txt.

Exit status is non-zero if any check fails.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}
IDENTIFIER_SCOPES = ("docs", "labs", "README.md", "ARCHITECTURE.md", "SECURITY.md")

ALLOWED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",       # loopback
        "0.0.0.0/32",        # unspecified
        "192.0.2.0/24",      # RFC 5737 documentation
        "198.51.100.0/24",   # RFC 5737 documentation
        "203.0.113.0/24",    # RFC 5737 documentation
        "160.79.104.0/23",   # published model provider API range (labs/openclaw)
    )
]

LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
EXPLICIT_ANCHOR_RE = re.compile(r'<a\s+(?:id|name)="([^"]+)"')
GUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
TENANT_RE = re.compile(r"\b[\w-]+\.onmicrosoft\.com\b", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?![\d.])")
FINDING_ROW_RE = re.compile(r"^\|\s*(\d+)\s*\|")

ALLOWLIST_FILE = ROOT / "scripts" / "consistency_allowlist.txt"
ALLOWED_VALUES = {
    line.split("#", 1)[0].strip()
    for line in (ALLOWLIST_FILE.read_text(encoding="utf-8").splitlines() if ALLOWLIST_FILE.exists() else [])
    if line.split("#", 1)[0].strip()
}

errors: list[str] = []


def fail(path: Path, line: int, check: str, message: str) -> None:
    errors.append(f"{path.relative_to(ROOT)}:{line}: [{check}] {message}")


def markdown_files() -> list[Path]:
    return sorted(
        p for p in ROOT.rglob("*.md") if not any(part in SKIP_DIRS for part in p.parts)
    )


def strip_code(lines: list[str]) -> list[tuple[int, str]]:
    """Return (line_number, text) pairs outside fenced code, with inline code removed."""
    out, fenced = [], False
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if not fenced:
            out.append((number, re.sub(r"`[^`]*`", "", line)))
    return out


def slugify(text: str) -> str:
    """GitHub-style heading anchor."""
    text = re.sub(r"<[^>]+>", "", text)                  # inline HTML
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links -> text
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


_anchor_cache: dict[Path, set[str]] = {}


def anchors(path: Path) -> set[str]:
    if path not in _anchor_cache:
        seen: dict[str, int] = {}
        found: set[str] = set()
        fenced = False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith(("```", "~~~")):
                fenced = not fenced
                continue
            if fenced:
                continue
            found.update(EXPLICIT_ANCHOR_RE.findall(line))
            match = HEADING_RE.match(line)
            if match:
                slug = slugify(match.group(2))
                count = seen.get(slug, 0)
                found.add(slug if count == 0 else f"{slug}-{count}")
                seen[slug] = count + 1
        _anchor_cache[path] = found
    return _anchor_cache[path]


def check_links(path: Path, lines: list[tuple[int, str]]) -> None:
    for number, text in lines:
        for target in LINK_RE.findall(text):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
                continue  # external (https:, mailto:, ...)
            file_part, _, fragment = target.partition("#")
            resolved = (path.parent / file_part).resolve() if file_part else path
            if file_part and not resolved.exists():
                fail(path, number, "links", f"missing target: {target}")
                continue
            if fragment and resolved.suffix == ".md" and fragment not in anchors(resolved):
                fail(path, number, "links", f"missing anchor: {target}")


def in_identifier_scope(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    return any(rel == s or rel.startswith(s + "/") for s in IDENTIFIER_SCOPES)


def check_identifiers(path: Path) -> None:
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        for guid in GUID_RE.findall(line):
            if guid in ALLOWED_VALUES:
                continue
            fail(path, number, "identifiers", f"GUID looks like an environment ID: {guid}")
        for domain in TENANT_RE.findall(line):
            if domain in ALLOWED_VALUES:
                continue
            fail(path, number, "identifiers", f"tenant domain: {domain}")
        for candidate in IPV4_RE.findall(line):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue  # version strings and similar
            if candidate not in ALLOWED_VALUES and not any(address in net for net in ALLOWED_NETWORKS):
                fail(path, number, "identifiers", f"IPv4 address outside allowlist: {candidate}")


def check_findings(path: Path, raw: list[str]) -> None:
    in_appendix, numbers, first_line = False, [], 0
    for number, line in enumerate(raw, start=1):
        if HEADING_RE.match(line):
            in_appendix = slugify(HEADING_RE.match(line).group(2)) == "appendix-findings"
            continue
        if in_appendix:
            match = FINDING_ROW_RE.match(line)
            if match:
                numbers.append(int(match.group(1)))
                first_line = first_line or number
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        fail(path, first_line, "findings", f"findings not numbered 1..{len(numbers)}: {numbers}")


def main() -> int:
    for path in markdown_files():
        raw = path.read_text(encoding="utf-8").splitlines()
        check_links(path, strip_code(raw))
        check_findings(path, raw)
    for path in sorted(p for p in ROOT.rglob("*") if p.is_file() and in_identifier_scope(p)):
        if not any(part in SKIP_DIRS for part in path.parts):
            check_identifiers(path)

    if errors:
        print(f"Consistency check failed ({len(errors)} issue(s)):")
        print("\n".join(f"  {e}" for e in errors))
        return 1
    print("Consistency check passed: links, identifiers, findings numbering.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
