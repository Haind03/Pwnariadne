"""Emit a debugger script that stops at suspicious call sites and dumps context.

The script is observe only: it sets breakpoints and prints state (registers,
stack, canary, GOT, heap) when a breakpoint hits. It never changes memory,
writes input, or redirects control flow.

It targets three front ends and picks the richest commands each one offers:

* pwndbg  -> context, telescope, canary, got, heap, bins, vis_heap_chunks
* GEF     -> context, telescope, canary, got, heap chunks, heap bins
* gdb     -> info registers, x/.. , backtrace

Every command is wrapped in a python guard, so a command a given front end does
not provide is skipped with a note instead of aborting the run.
"""

from __future__ import annotations

from pwnariadne import SIGNATURE, __version__
from pwnariadne.classify.finding import Finding
from pwnariadne.integrations.tools import DebuggerFlavor

# Per flavor, the base context dump run on every breakpoint hit.
_BASE: dict[DebuggerFlavor, list[str]] = {
    DebuggerFlavor.PWNDBG: ["context", "telescope $sp 24"],
    DebuggerFlavor.GEF: ["context", "telescope $sp 24"],
    DebuggerFlavor.GDB: ["info registers", "x/24xg $sp", "bt"],
}

# Per flavor, extra commands keyed by bug class, run after the base dump.
_EXTRA: dict[str, dict[DebuggerFlavor, list[str]]] = {
    "stack-buffer-overflow": {
        DebuggerFlavor.PWNDBG: ["canary", "telescope $sp 40"],
        DebuggerFlavor.GEF: ["canary", "telescope $sp 40"],
        DebuggerFlavor.GDB: ["x/40xg $sp"],
    },
    "buffer-overflow": {
        DebuggerFlavor.PWNDBG: ["canary", "telescope $sp 40"],
        DebuggerFlavor.GEF: ["canary", "telescope $sp 40"],
        DebuggerFlavor.GDB: ["x/40xg $sp"],
    },
    "format-string": {
        DebuggerFlavor.PWNDBG: ["got", "telescope $sp 20"],
        DebuggerFlavor.GEF: ["got", "telescope $sp 20"],
        DebuggerFlavor.GDB: ["x/20xg $sp"],
    },
    "use-after-free / double-free": {
        DebuggerFlavor.PWNDBG: ["heap", "bins", "vis_heap_chunks"],
        DebuggerFlavor.GEF: ["heap chunks", "heap bins"],
        DebuggerFlavor.GDB: ["info proc mappings"],
    },
    "heap-overflow": {
        DebuggerFlavor.PWNDBG: ["heap", "bins", "vis_heap_chunks"],
        DebuggerFlavor.GEF: ["heap chunks", "heap bins"],
        DebuggerFlavor.GDB: ["info proc mappings"],
    },
    "command-injection": {
        DebuggerFlavor.PWNDBG: ["telescope $sp 12"],
        DebuggerFlavor.GEF: ["telescope $sp 12"],
        DebuggerFlavor.GDB: ["x/12xg $sp"],
    },
}


def _header(flavor: DebuggerFlavor) -> str:
    return f"""\
# Pwnariadne {__version__} generated debugger script
# Author: {SIGNATURE}
# Target front end: {flavor}
#
# Observe only: sets breakpoints and prints state. It does not modify memory
# or redirect execution. Review before running.
#
# Usage:
#   gdb -q -x this_script.gdb ./target
#   (pwndbg or GEF is used automatically if your gdbinit loads it)

set pagination off
set backtrace past-main on

python
import gdb

def pa_safe(cmd):
    \"\"\"Run a debugger command, printing a note if it is unavailable.\"\"\"
    try:
        gdb.execute(cmd)
    except gdb.error as exc:
        print("[pwnariadne] skipped '%s' (%s)" % (cmd, exc))
end
"""


_FOOTER = """\

printf "\\n[pwnariadne] %d breakpoint(s) armed. Run with 'run' or 'r'.\\n", $pa_count
"""


def generate(
    findings: list[Finding],
    target: str | None = None,
    flavor: DebuggerFlavor = DebuggerFlavor.PWNDBG,
) -> str:
    """Return the full text of a debugger script for the given findings."""

    lines: list[str] = [_header(flavor)]
    if target:
        lines.append(f"file {target}\n")
    lines.append("set $pa_count = 0\n")

    for idx, finding in enumerate(findings, start=1):
        block = _breakpoint_block(idx, finding, flavor)
        if block:
            lines.append(block)

    lines.append(_FOOTER)
    return "\n".join(lines)


def _dump_commands(bug_class: str, flavor: DebuggerFlavor) -> list[str]:
    commands = list(_BASE[flavor])
    extra = _EXTRA.get(bug_class, {}).get(flavor, [])
    commands.extend(extra)
    return commands


def _breakpoint_block(idx: int, f: Finding, flavor: DebuggerFlavor) -> str:
    where = _break_location(f)
    if where is None:
        return ""

    watch = f.sink.watch.replace('"', '\\"')
    label = f"#{idx} {f.sink.name} [{f.bug_class}] {f.location}"
    dump = "\n".join(
        f'  python pa_safe("{cmd}")' for cmd in _dump_commands(f.bug_class, flavor)
    )
    return (
        f"# {label}\n"
        f"break {where}\n"
        f"set $pa_count = $pa_count + 1\n"
        f"commands\n"
        f'  printf "\\n==== [pwnariadne] hit {f.sink.name} ({f.bug_class}) ====\\n"\n'
        f'  printf "watch: {watch}\\n"\n'
        f"{dump}\n"
        f"  continue\n"
        f"end\n"
    )


def _break_location(f: Finding) -> str | None:
    if f.address is not None:
        return f"*{f.address:#x}"
    if f.source_file is not None and f.line is not None:
        return f"{f.source_file}:{f.line}"
    return None
