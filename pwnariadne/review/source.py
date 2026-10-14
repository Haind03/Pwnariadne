"""C source review.

Two backends share one entry point:

* tree-sitter (preferred): parses the real syntax tree, so it knows the
  enclosing function, handles calls split across lines, and skips a constant
  ``printf`` format string instead of flagging it.
* regex line scanner (fallback): zero extra dependencies, favours recall, so
  every hit is a lead to verify.

``review_source`` picks tree-sitter automatically when it is importable, and
falls back to the regex scanner otherwise. Pass ``backend="regex"`` to force the
scanner, or ``backend="treesitter"`` to require the parser.
"""

from __future__ import annotations

import re
from pathlib import Path

from pwnariadne.classify.finding import Finding
from pwnariadne.review import treesitter_c
from pwnariadne.review.sinks import SINKS, lookup

# Build one pattern: a sink name as a whole word, immediately followed by "(".
_NAMES = sorted({s.name for s in SINKS}, key=len, reverse=True)
_CALL_RE = re.compile(r"\b(" + "|".join(map(re.escape, _NAMES)) + r")\s*\(")
# Lines that are clearly comments or string-literal noise are skipped crudely.
_COMMENT_RE = re.compile(r"^\s*(//|\*|/\*)")


def review_source(paths: list[str], backend: str = "auto") -> list[Finding]:
    """Scan the given .c/.h files (or directories) for sink calls.

    ``backend`` is "auto" (tree-sitter if available, else regex), "treesitter",
    or "regex".
    """

    if backend == "treesitter" or (backend == "auto" and treesitter_c.available()):
        return treesitter_c.review_sources(paths)

    findings: list[Finding] = []
    for raw in paths:
        for file in _expand(raw):
            findings.extend(_scan_file(file))
    return sorted(findings, key=lambda f: f.severity, reverse=True)


def active_backend(backend: str = "auto") -> str:
    """Report which backend ``review_source`` would use for ``backend``."""

    if backend == "regex":
        return "regex"
    if backend == "treesitter":
        return "treesitter"
    return "treesitter" if treesitter_c.available() else "regex"


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
