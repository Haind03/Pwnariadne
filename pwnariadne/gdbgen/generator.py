"""Emit a GDB script that stops at each finding and dumps useful context.

The generated script only *observes*: it sets breakpoints and prints registers,
the stack, and a backtrace when a breakpoint hits. It never changes memory,
writes input, or alters control flow. It works with plain GDB and is enhanced
automatically if pwndbg or GEF is loaded (their `context`/`heap` commands are
invoked when present).
"""

from __future__ import annotations

from pwnariadne import SIGNATURE, __version__
from pwnariadne.classify.finding import Finding

_HEADER = f"""\
# Pwnariadne {__version__} — generated GDB script
# Author: {SIGNATURE}
#
# Observe-only: this script sets breakpoints and prints state. It does not
# modify memory or redirect execution. Review before running.
#
# Usage:
#   gdb -q -x this_script.gdb ./target
# or inside an existing session:
#   source this_script.gdb

set pagination off
set backtrace past-main on

# Pretty context from pwndbg / GEF when available; harmless otherwise.
define pa_context
  if $_isvoid($pc) == 0
    printf "\\n--- registers ---\\n"
    info registers
    printf "\\n--- stack (16 words) ---\\n"
    x/16xg $sp
    printf "\\n--- backtrace ---\\n"
    bt
  end
end
"""

_FOOTER = """\

printf "\\n[pwnariadne] %d breakpoint(s) armed. Run with 'run' or 'r'.\\n", $pa_count
"""


def generate(findings: list[Finding], target: str | None = None) -> str:
    """Return the full text of a GDB script for the given findings."""

    lines: list[str] = [_HEADER]
    if target:
        lines.append(f"file {target}\n")
    lines.append("set $pa_count = 0\n")

    for idx, finding in enumerate(findings, start=1):
        lines.append(_breakpoint_block(idx, finding))

    lines.append(_FOOTER)
    return "\n".join(lines)


def _breakpoint_block(idx: int, f: Finding) -> str:
    where = _break_location(f)
    if where is None:
        return ""

    watch = f.sink.watch.replace('"', '\\"')
    label = f"#{idx} {f.sink.name} [{f.bug_class}] {f.location}"
    return (
        f"# {label}\n"
        f"break {where}\n"
        f"set $pa_count = $pa_count + 1\n"
        f"commands\n"
        f'  printf "\\n==== [pwnariadne] hit {f.sink.name} ({f.bug_class}) ====\\n"\n'
        f'  printf "watch: {watch}\\n"\n'
        f"  pa_context\n"
        f"  continue\n"
        f"end\n"
    )


def _break_location(f: Finding) -> str | None:
    """A location string GDB understands."""

    if f.address is not None:
        return f"*{f.address:#x}"
    if f.source_file is not None and f.line is not None:
        return f"{f.source_file}:{f.line}"
    return None
