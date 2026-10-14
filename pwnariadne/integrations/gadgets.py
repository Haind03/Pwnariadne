"""Enumerate useful ROP gadgets by driving ROPgadget or ropper.

This is read only reconnaissance: it lists gadget addresses the same way the
underlying CLI tools do, so an analyst can study reachability. It assembles no
chain and writes no payload. If neither tool is installed, it returns an empty
result with a note instead of failing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

# Gadgets most often studied when reasoning about control flow on x86 and
# x86-64. Each key is a label, each value a regex matched against a gadget line.
_WANTED: dict[str, re.Pattern[str]] = {
    "pop rdi ; ret": re.compile(r"\bpop rdi\b.*\bret\b"),
    "pop rsi ; ret": re.compile(r"\bpop rsi\b.*\bret\b"),
    "pop rdx ; ret": re.compile(r"\bpop rdx\b.*\bret\b"),
    "pop rax ; ret": re.compile(r"\bpop rax\b.*\bret\b"),
    "pop rsp ; ret": re.compile(r"\bpop rsp\b.*\bret\b"),
    "leave ; ret": re.compile(r"\bleave\b.*\bret\b"),
    "ret": re.compile(r":\s*ret$"),
    "syscall": re.compile(r"\bsyscall\b"),
    "int 0x80": re.compile(r"\bint\s+0x80\b"),
}

_LINE_RE = re.compile(r"^(0x[0-9a-fA-F]+)\s*:\s*(.+)$")


@dataclass
class GadgetResult:
    """Curated gadgets discovered in a binary, plus provenance."""

    tool: str | None
    gadgets: dict[str, int] = field(default_factory=dict)  # label -> address
    total_scanned: int = 0
    note: str = ""


def enumerate_gadgets(path: str, timeout: int = 60) -> GadgetResult:
    """Return a small, curated set of useful gadgets found in ``path``."""

    if shutil.which("ROPgadget"):
        return _with_ropgadget(path, timeout)
    if shutil.which("ropper"):
        return _with_ropper(path, timeout)
    return GadgetResult(
        tool=None,
        note="no gadget finder installed (pip install ROPgadget, or apt install ropper)",
    )


def _collect(lines: list[str]) -> tuple[dict[str, int], int]:
    found: dict[str, int] = {}
    scanned = 0
    for line in lines:
        match = _LINE_RE.match(line.strip())
        if not match:
            continue
        scanned += 1
        addr = int(match.group(1), 16)
        insn = match.group(2).strip()
        for label, pattern in _WANTED.items():
            if label in found:
                continue
            if pattern.search(insn):
                found[label] = addr
    return found, scanned


def _run(cmd: list[str], timeout: int) -> list[str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.stdout.splitlines()


def _with_ropgadget(path: str, timeout: int) -> GadgetResult:
    try:
        lines = _run(["ROPgadget", "--binary", path], timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        return GadgetResult(tool="ROPgadget", note=f"ROPgadget failed: {exc}")
    found, scanned = _collect(lines)
    return GadgetResult(tool="ROPgadget", gadgets=found, total_scanned=scanned)


def _with_ropper(path: str, timeout: int) -> GadgetResult:
    try:
        lines = _run(["ropper", "--file", path, "--nocolor"], timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        return GadgetResult(tool="ropper", note=f"ropper failed: {exc}")
    found, scanned = _collect(lines)
    return GadgetResult(tool="ropper", gadgets=found, total_scanned=scanned)
