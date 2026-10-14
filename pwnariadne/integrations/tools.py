"""Detect and describe the external tools Pwnariadne can orchestrate.

This module only *discovers* capabilities. It runs nothing on its own; callers
decide when to invoke a detected tool. Detection is cheap (PATH lookups and
import probes) and fully side effect free.
"""

from __future__ import annotations

import enum
import importlib.util
import os
import shutil
from dataclasses import dataclass, field


class DebuggerFlavor(str, enum.Enum):
    """Which debugger front end a generated script should target."""

    PWNDBG = "pwndbg"
    GEF = "gef"
    GDB = "gdb"

    def __str__(self) -> str:  # nicer CLI echo
        return self.value


@dataclass
class Tool:
    """A single external tool and whether it is available."""

    name: str
    kind: str  # "debugger-plugin", "gadget", "libc", "library", "cli"
    available: bool
    path: str | None = None
    note: str = ""


@dataclass
class Toolbox:
    """The set of tools found on this machine."""

    tools: list[Tool] = field(default_factory=list)

    def get(self, name: str) -> Tool | None:
        for tool in self.tools:
            if tool.name == name:
                return tool
        return None

    def has(self, name: str) -> bool:
        tool = self.get(name)
        return bool(tool and tool.available)

    def available(self) -> list[Tool]:
        return [t for t in self.tools if t.available]

    def missing(self) -> list[Tool]:
        return [t for t in self.tools if not t.available]


def _has_module(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _gdbinit_mentions(keyword: str) -> str | None:
    """Return the gdbinit path if it loads the given plugin keyword."""

    candidates = [
        os.path.expanduser("~/.gdbinit"),
        os.path.expanduser("~/.config/gdb/gdbinit"),
    ]
    for path in candidates:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                if keyword.lower() in fh.read().lower():
                    return path
        except OSError:
            continue
    return None


def detect_debugger(prefer: DebuggerFlavor | None = None) -> DebuggerFlavor:
    """Pick the richest debugger front end available.

    Order of preference: an explicit ``prefer``, then pwndbg, then GEF, then
    plain GDB. pwndbg and GEF are detected either on PATH or via a gdbinit that
    loads them.
    """

    if prefer is not None:
        return prefer

    pwndbg = shutil.which("pwndbg") or _gdbinit_mentions("pwndbg")
    if pwndbg:
        return DebuggerFlavor.PWNDBG
    gef = _gdbinit_mentions("gef") or shutil.which("gef")
    if gef:
        return DebuggerFlavor.GEF
    return DebuggerFlavor.GDB


def detect_toolbox() -> Toolbox:
    """Probe the machine for every tool Pwnariadne knows how to use."""

    tools: list[Tool] = []

    # Debuggers and their plugins.
    gdb_path = shutil.which("gdb")
    tools.append(
        Tool("gdb", "cli", bool(gdb_path), gdb_path, "core debugger")
    )
    pwndbg_init = _gdbinit_mentions("pwndbg")
    pwndbg_path = shutil.which("pwndbg")
    tools.append(
        Tool(
            "pwndbg",
            "debugger-plugin",
            bool(pwndbg_path or pwndbg_init),
            pwndbg_path or pwndbg_init,
            "rich context, heap, telescope, got/bins",
        )
    )
    gef_init = _gdbinit_mentions("gef")
    tools.append(
        Tool("gef", "debugger-plugin", bool(gef_init), gef_init, "alt GDB enhancer")
    )

    # Gadget finders.
    for name, note in (
        ("ROPgadget", "ROP/JOP gadget enumeration"),
        ("ropper", "alt gadget finder"),
    ):
        path = shutil.which(name)
        tools.append(Tool(name, "gadget", bool(path), path, note))
    tools.append(
        Tool(
            "ropgadget-lib",
            "library",
            _has_module("ropgadget"),
            None,
            "ROPgadget as a python module",
        )
    )

    # libc helpers.
    one_gadget = shutil.which("one_gadget")
    tools.append(
        Tool("one_gadget", "libc", bool(one_gadget), one_gadget, "libc one-shot gadgets")
    )

    # Source parsing backend.
    tools.append(
        Tool(
            "tree-sitter-c",
            "library",
            _has_module("tree_sitter") and _has_module("tree_sitter_c"),
            None,
            "accurate C source review",
        )
    )

    # Reachability engine.
    tools.append(
        Tool(
            "angr",
            "library",
            _has_module("angr"),
            None,
            "static reachability (CFG) from entry",
        )
    )

    # pwntools and checksec.
    tools.append(
        Tool("pwntools", "library", _has_module("pwn"), None, "ELF/checksec/ROP helpers")
    )
    checksec = shutil.which("checksec")
    tools.append(
        Tool("checksec", "cli", bool(checksec), checksec, "mitigation report")
    )

    return Toolbox(tools=tools)
