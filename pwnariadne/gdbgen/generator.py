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
        DebuggerFlavor.PWNDBG: ["got", "pa_fmt"],
        DebuggerFlavor.GEF: ["got", "pa_fmt"],
        DebuggerFlavor.GDB: ["pa_fmt"],
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
    offsets=None,
    onegadget=None,
) -> str:
    """Return the full text of a debugger script for the given findings.

    ``offsets`` (OverflowOffset list) annotates the matching breakpoints with the
    computed padding to the saved RIP and a live ``$rbp`` dump. ``onegadget``
    (OneGadgetResult) adds a ``pa_onegadget`` helper that checks each one-gadget's
    constraints at the current stop.
    """

    offset_by_addr = {o.call_address: o for o in (offsets or [])}

    lines: list[str] = [_header(flavor)]
    if target:
        lines.append(f"file {target}\n")
    if any(f.bug_class == "format-string" for f in findings):
        lines.append(_fmt_helper())
    if onegadget is not None and getattr(onegadget, "gadgets", None):
        lines.append(_onegadget_helper(onegadget))
    lines.append("set $pa_count = 0\n")

    for idx, finding in enumerate(findings, start=1):
        block = _breakpoint_block(idx, finding, flavor, offset_by_addr.get(finding.address))
        if block:
            lines.append(block)

    lines.append(_FOOTER)
    return "\n".join(lines)


def _constraint_to_gdb(c: str) -> str:
    """Translate a one_gadget constraint into a GDB command that shows its value.

    e.g. "rsp & 0xf == 0"  -> p/x $rsp & 0xf   (want 0)
         "[rsp+0x40] == NULL" -> x/gx $rsp+0x40   (want 0)
         "rcx == NULL"      -> p/x $rcx         (want 0)
    """

    import re as _re

    expr = c.strip()
    mem = _re.match(r"^\[([^\]]+)\]\s*==\s*(NULL|0x0|0)\b", expr)
    if mem:
        addr = _re.sub(r"\b([re][a-z0-9]+)\b", r"$\1", mem.group(1))
        return f'  printf "  [{mem.group(1)}] (want 0): "\n  x/gx {addr}'
    left = expr.split("==")[0].strip()
    gdb_expr = _re.sub(r"\b([re][a-z0-9]+)\b", r"$\1", left)
    return f'  printf "  {expr}: "\n  p/x {gdb_expr}'


def _fmt_helper(stack_slots: int = 14) -> str:
    """A GDB command that labels each value a printf would read as %N$.

    %1$..%5$ are the register varargs (rsi, rdx, rcx, r8, r9) and %6$ onward are
    the stack qwords at the format-string call, so you can see which index
    reaches your controlled input.
    """

    lines = [
        "# Format-string helper. At a format-string breakpoint run: pa_fmt",
        "define pa_fmt",
        '  printf "%%1$ (rsi) = 0x%lx\\n", $rsi',
        '  printf "%%2$ (rdx) = 0x%lx\\n", $rdx',
        '  printf "%%3$ (rcx) = 0x%lx\\n", $rcx',
        '  printf "%%4$ (r8)  = 0x%lx\\n", $r8',
        '  printf "%%5$ (r9)  = 0x%lx\\n", $r9',
    ]
    for i in range(stack_slots):
        idx = 6 + i
        off = i * 8
        lines.append(
            f'  printf "%%{idx}$  = 0x%lx\\n", *(unsigned long*)($sp+{off})'
        )
    lines.append("end\n")
    return "\n".join(lines)


def _onegadget_helper(onegadget) -> str:
    """A GDB command that prints each one-gadget's constraint values."""

    blocks = [
        "# one_gadget constraint checker. At the hijack point run: pa_onegadget",
        f"# libc: {onegadget.libc}",
        "define pa_onegadget",
    ]
    for g in onegadget.gadgets:
        blocks.append(f'  printf "\\n== one_gadget {g.offset:#x}  {g.call} ==\\n"')
        if not g.constraints:
            blocks.append('  printf "  (no constraints)\\n"')
        for c in g.constraints:
            blocks.append(_constraint_to_gdb(c))
    blocks.append("end\n")
    return "\n".join(blocks)


def _dump_commands(bug_class: str, flavor: DebuggerFlavor) -> list[str]:
    commands = list(_BASE[flavor])
    extra = _EXTRA.get(bug_class, {}).get(flavor, [])
    commands.extend(extra)
    return commands


def _breakpoint_block(idx: int, f: Finding, flavor: DebuggerFlavor, offset=None) -> str:
    where = _break_location(f)
    if where is None:
        return ""

    watch = f.sink.watch.replace('"', '\\"')
    label = f"#{idx} {f.sink.name} [{f.bug_class}] {f.location}"
    dump = "\n".join(
        f'  python pa_safe("{cmd}")' for cmd in _dump_commands(f.bug_class, flavor)
    )
    off_lines = ""
    if offset is not None:
        off_lines = (
            f'  printf "offset buf -> saved RIP = {offset.offset_to_ret} '
            f'({offset.offset_to_ret:#x}); canary slot at buf+{offset.offset_to_canary} '
            f'(rbp-8)\\n"\n'
            f'  printf "saved rbp/ret (rbp, rbp+8):\\n"\n'
            f"  x/2gx $rbp\n"
        )
    return (
        f"# {label}\n"
        f"break {where}\n"
        f"set $pa_count = $pa_count + 1\n"
        f"commands\n"
        f'  printf "\\n==== [pwnariadne] hit {f.sink.name} ({f.bug_class}) ====\\n"\n'
        f'  printf "watch: {watch}\\n"\n'
        f"{off_lines}"
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
