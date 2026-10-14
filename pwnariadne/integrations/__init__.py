"""Integrations with external pwn tooling.

Pwnariadne does not reimplement the ecosystem; it orchestrates it. This package
detects which well known tools are installed (pwndbg, GEF, ROPgadget, ropper,
one_gadget, pwntools, checksec) and drives the read only ones to enrich a
review. Every integration degrades gracefully: if a tool is absent, the feature
that needs it is skipped with a clear note, never an error.
"""

from pwnariadne.integrations.tools import (
    DebuggerFlavor,
    Toolbox,
    detect_debugger,
    detect_toolbox,
)

__all__ = [
    "DebuggerFlavor",
    "Toolbox",
    "detect_debugger",
    "detect_toolbox",
]
