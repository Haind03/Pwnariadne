"""Lightweight C source review.

A regex line scanner that flags calls to known sink functions. It is
deliberately simple (no full parser) so it runs with zero extra dependencies;
it favours recall over precision, so treat every hit as a lead to verify, not
a confirmed bug. A tree-sitter backend can replace this later for accuracy.
"""

from __future__ import annotations

import re
from pathlib import Path

from pwnariadne.classify.finding import Finding
from pwnariadne.review.sinks import SINKS, lookup

# Build one pattern: a sink name as a whole word, immediately followed by "(".
_NAMES = sorted({s.name for s in SINKS}, key=len, reverse=True)
_CALL_RE = re.compile(r"\b(" + "|".join(map(re.escape, _NAMES)) + r")\s*\(")
# Lines that are clearly comments or string-literal noise are skipped crudely.
_COMMENT_RE = re.compile(r"^\s*(//|\*|/\*)")


def review_source(paths: list[str]) -> list[Finding]:
    """Scan the given .c/.h files (or directories) for sink calls."""

    findings: list[Finding] = []
    for raw in paths:
        for file in _expand(raw):
            findings.extend(_scan_file(file))
    return sorted(findings, key=lambda f: f.severity, reverse=True)


def _expand(raw: str) -> list[Path]:
    p = Path(raw)
    if p.is_dir():
        return [f for ext in ("*.c", "*.h", "*.cc", "*.cpp") for f in p.rglob(ext)]
    return [p] if p.is_file() else []


def _scan_file(file: Path) -> list[Finding]:
    try:
        text = file.read_text(errors="replace")
    except OSError:
        return []

    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _COMMENT_RE.match(line):
            continue
        for match in _CALL_RE.finditer(line):
            sink = lookup(match.group(1))
            if sink is None:
                continue
            out.append(
                Finding(
                    sink=sink,
                    address=None,
                    in_function="?",
                    source_file=str(file),
                    line=lineno,
                    snippet=line.strip(),
                )
            )
    return out
