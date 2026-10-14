"""Render analysis results in several formats.

- terminal: a rich table for interactive use.
- markdown: a document suitable for a write-up or an audit note.
- json: machine-readable, for piping into other tooling.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from pwnariadne import SIGNATURE, __version__
from pwnariadne.classify.finding import Finding
from pwnariadne.core.elf import IndirectCall, Mitigations
from pwnariadne.core.offsets import OverflowOffset
from pwnariadne.integrations.angr_reach import ReachResult
from pwnariadne.integrations.gadgets import GadgetResult
from pwnariadne.integrations.libc import ChecksecResult, OneGadgetResult
from pwnariadne.integrations.tools import Toolbox
from pwnariadne.techniques import TechniqueHint


def print_toolbox(toolbox: Toolbox, console: Console | None = None) -> None:
    """Show which external tools Pwnariadne detected on this machine."""

    console = console or Console()
    table = Table(title="Detected toolbox")
    table.add_column("Tool", style="bold")
    table.add_column("Kind")
    table.add_column("Status")
    table.add_column("Note")
    for tool in toolbox.tools:
        status = "[green]available[/]" if tool.available else "[dim]absent[/]"
        table.add_row(tool.name, tool.kind, status, tool.note)
    console.print(table)


def to_endpoints(findings: list[Finding]) -> str:
    """Just the trigger points, one per line: greppable and pipe-friendly.

    Format: ``<location>\t<sink>\t<bug_class>``. For a binary finding the
    location is the hex address; for a source finding it is ``file:line``.
    """

    lines: list[str] = []
    for f in findings:
        where = f"{f.address:#x}" if f.address is not None else f.location
        row = f"{where}\t{f.sink.name}\t{f.bug_class}"
        if f.taint:
            row += f"\t{f.taint}"
        lines.append(row)
    return "\n".join(lines)


def to_json(
    findings: list[Finding],
    mitigations: Mitigations | None,
    techniques: list[TechniqueHint] | None = None,
    gadgets: GadgetResult | None = None,
    onegadget: OneGadgetResult | None = None,
    checksec: ChecksecResult | None = None,
    indirect: list[IndirectCall] | None = None,
    reachability: ReachResult | None = None,
    offsets: list[OverflowOffset] | None = None,
    got: dict | None = None,
) -> str:
    payload = {
        "tool": "pwnariadne",
        "version": __version__,
        "author": SIGNATURE,
        "mitigations": mitigations.as_dict() if mitigations else None,
        "got": {sym: hex(addr) for sym, addr in (got or {}).items()},
        "overflow_offsets": [
            {
                "sink": o.sink,
                "address": hex(o.call_address),
                "function": o.in_function,
                "offset_to_saved_rbp": o.offset_to_saved_rbp,
                "offset_to_ret": o.offset_to_ret,
                "offset_to_ret_hex": hex(o.offset_to_ret),
                "offset_to_canary": o.offset_to_canary,
                "confidence": o.confidence,
                "asm": o.asm,
            }
            for o in (offsets or [])
        ],
        "indirect_calls": [
            {
                "address": hex(ic.address),
                "function": ic.in_function,
                "mnemonic": ic.mnemonic,
                "operand": ic.operand,
            }
            for ic in (indirect or [])
        ],
        "reachability": (
            {
                "available": reachability.available,
                "note": reachability.note,
                "reachable": {hex(a): v for a, v in reachability.reachable.items()},
            }
            if reachability
            else None
        ),
        "checksec_pwntools": (
            checksec.data if checksec and checksec.available else None
        ),
        "one_gadget": (
            {
                "libc": onegadget.libc,
                "offsets": [hex(o) for o in onegadget.offsets],
                "gadgets": [
                    {
                        "offset": hex(g.offset),
                        "call": g.call,
                        "constraints": g.constraints,
                    }
                    for g in onegadget.gadgets
                ],
                "note": onegadget.note,
            }
            if onegadget
            else None
        ),
        "gadgets": (
            {
                "tool": gadgets.tool,
                "scanned": gadgets.total_scanned,
                "note": gadgets.note,
                "found": {k: hex(v) for k, v in gadgets.gadgets.items()},
            }
            if gadgets
            else None
        ),
        "techniques": [
            {
                "name": t.name,
                "relevance": t.relevance,
                "gate": t.gate,
                "confidence": t.confidence,
                "present": t.present,
                "missing": t.missing,
                "references": t.references,
            }
            for t in (techniques or [])
        ],
        "findings": [
            {
                "sink": f.sink.name,
                "bug_class": f.bug_class,
                "severity": f.severity,
                "location": f.location,
                "address": f.address,
                "function": f.in_function,
                "source_file": f.source_file,
                "line": f.line,
                "snippet": f.snippet,
                "taint": f.taint,
                "why": f.sink.why,
                "watch": f.sink.watch,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(
    findings: list[Finding],
    mitigations: Mitigations | None,
    techniques: list[TechniqueHint] | None = None,
    gadgets: GadgetResult | None = None,
    onegadget: OneGadgetResult | None = None,
    checksec: ChecksecResult | None = None,
    indirect: list[IndirectCall] | None = None,
    reachability: ReachResult | None = None,
    offsets: list[OverflowOffset] | None = None,
    got: dict | None = None,
) -> str:
    out: list[str] = [
        "# Pwnariadne report",
        "",
        f"_Generated by Pwnariadne {__version__}: {SIGNATURE}_",
        "",
    ]
    if mitigations:
        m = mitigations
        out += [
            "## Mitigations",
            "",
            f"- Arch: `{m.arch}` ({m.bits}-bit)",
            f"- RELRO: `{m.relro}`",
            f"- Stack canary: `{m.canary}`",
            f"- NX: `{m.nx}`",
            f"- PIE: `{m.pie}`",
            "",
        ]
        if m.pie:
            out += ["> PIE is enabled: every address below is a file offset from "
                    "the image base. Leak the base at runtime and add it.", ""]

    if got:
        writable = not (mitigations and mitigations.relro == "full")
        state = "writable (overwrite targets)" if writable else "read-only (Full RELRO)"
        out += ["## GOT entries", "", f"GOT is {state}.", "",
                "| Symbol | GOT address |", "|--------|-------------|"]
        for sym, addr in got.items():
            out.append(f"| `{sym}` | `{addr:#x}` |")
        out.append("")

    if offsets:
        out += ["## Overflow offsets (computed from the assembly)", "",
                "> Padding to reach the saved return address, read off the function's "
                "own instructions.", "",
                "| Sink | Function | To saved RBP | To saved RIP |",
                "|------|----------|--------------|--------------|"]
        for o in offsets:
            rbp_cell = (
                "n/a"
                if o.offset_to_saved_rbp < 0
                else f"{o.offset_to_saved_rbp} (`{o.offset_to_saved_rbp:#x}`)"
            )
            out.append(
                f"| `{o.sink}` @ `{o.call_address:#x}` | `{o.in_function}` "
                f"| {rbp_cell} | {o.offset_to_ret} (`{o.offset_to_ret:#x}`) [{o.frame_kind}] |"
            )
        out.append("")
        if mitigations and mitigations.canary:
            out.append(
                "> Stack canary is enabled: the 8 bytes at `rbp-8` "
                f"(buffer + {offsets[0].offset_to_canary}) must be leaked and kept "
                "intact before the overflow reaches the saved RIP."
            )
            out.append("")
        for o in offsets:
            out.append(f"<details><summary>{o.sink} @ {o.call_address:#x} assembly</summary>")
            out.append("")
            out.append("```")
            out += o.asm
            out.append("```")
            out.append("</details>")
            out.append("")

    out += ["## Findings", ""]
    if not findings:
        out.append("_No sink calls found._")
    else:
        out += ["| # | Severity | Sink | Bug class | Taint | Location | Watch |",
                "|---|----------|------|-----------|-------|----------|-------|"]
        for i, f in enumerate(findings, start=1):
            out.append(
                f"| {i} | {f.severity} | `{f.sink.name}` | {f.bug_class} "
                f"| {f.taint or '-'} | `{f.location}` | {f.sink.watch} |"
            )

    if techniques:
        out += ["", "## Candidate techniques to investigate", "",
                "> Advisory only. Conditions observed, not confirmed exploits.", ""]
        for t in techniques:
            out.append(f"### {t.name}  _(confidence: {t.confidence})_")
            out.append(f"- **Relevance:** {t.relevance}")
            out.append(f"- **Gate:** {t.gate}")
            if t.present:
                out.append(f"- **Present:** {', '.join(t.present)}")
            if t.missing:
                out.append(f"- **Missing:** {', '.join(t.missing)}")
            for ref in t.references:
                out.append(f"- Ref: {ref}")
            out.append("")

    if checksec is not None and checksec.available:
        out += ["", "## checksec (pwntools cross check)", ""]
        for key, val in checksec.data.items():
            out.append(f"- {key}: `{val}`")
        out.append("")

    if gadgets is not None:
        out += ["", "## ROP gadgets (read only reconnaissance)", ""]
        if gadgets.gadgets:
            out.append(f"Found via `{gadgets.tool}` ({gadgets.total_scanned} scanned):")
            out.append("")
            out += ["| Gadget | Address |", "|--------|---------|"]
            for label, addr in gadgets.gadgets.items():
                out.append(f"| `{label}` | `{addr:#x}` |")
        else:
            out.append(f"_No curated gadgets found. {gadgets.note}_")
        out.append("")

    if indirect:
        out += ["", "## Indirect dispatch points (unresolved targets)", "",
                "> Function pointer / vtable / GOT calls. The target is not "
                "statically known; set a breakpoint to see it at runtime.", "",
                "| Address | Function | Instruction |",
                "|---------|----------|-------------|"]
        for ic in indirect:
            out.append(f"| `{ic.address:#x}` | `{ic.in_function}` | `{ic.mnemonic} {ic.operand}` |")
        out.append("")

    if reachability is not None:
        out += ["", "## Static reachability from entry (angr)", ""]
        if not reachability.available:
            out.append(f"_Not available. {reachability.note}_")
        elif not reachability.reachable:
            out.append(f"_{reachability.note or 'no addresses checked'}_")
        else:
            out += ["| Address | Reachable from entry |", "|---------|----------------------|"]
            for addr, ok in reachability.reachable.items():
                out.append(f"| `{addr:#x}` | {'yes' if ok else 'no'} |")
        out.append("")

    if onegadget is not None:
        out += ["", "## libc one_gadget (read only reconnaissance)", ""]
        if onegadget.gadgets:
            out.append(f"Candidates in `{onegadget.libc}` (satisfy the constraints):")
            out.append("")
            for g in onegadget.gadgets:
                out.append(f"- `{g.offset:#x}`  {g.call}")
                for c in g.constraints:
                    out.append(f"    - constraint: `{c}`")
            out.append("")
        elif onegadget.offsets:
            out.append(f"Offsets in `{onegadget.libc}`:")
            out.append("")
            for off in onegadget.offsets:
                out.append(f"- `{off:#x}`")
        else:
            out.append(f"_No one_gadget offsets. {onegadget.note}_")
        out.append("")

    return "\n".join(out) + "\n"


def to_terminal(
    findings: list[Finding],
    mitigations: Mitigations | None,
    console: Console | None = None,
    techniques: list[TechniqueHint] | None = None,
    gadgets: GadgetResult | None = None,
    onegadget: OneGadgetResult | None = None,
    checksec: ChecksecResult | None = None,
    indirect: list[IndirectCall] | None = None,
    reachability: ReachResult | None = None,
    offsets: list[OverflowOffset] | None = None,
    got: dict | None = None,
) -> None:
    console = console or Console()
    console.print(f"[bold cyan]Pwnariadne {__version__}[/]: {SIGNATURE}")

    if mitigations:
        m = mitigations
        console.print(
            f"[bold]Mitigations:[/] arch={m.arch}/{m.bits} relro={m.relro} "
            f"canary={m.canary} nx={m.nx} pie={m.pie}"
        )
    if checksec is not None and checksec.available:
        console.print(f"[dim]checksec (pwntools): {checksec.data}[/]")
    if mitigations and mitigations.pie:
        console.print(
            "[yellow]PIE enabled:[/] addresses below are file offsets; "
            "add the leaked image base at runtime"
        )

    if got:
        writable = not (mitigations and mitigations.relro == "full")
        state = "[red]writable[/]" if writable else "[green]read-only[/]"
        gtab = Table(title=f"GOT entries ({state} )")
        gtab.add_column("Symbol", style="bold")
        gtab.add_column("GOT address")
        for sym, addr in got.items():
            gtab.add_row(sym, f"{addr:#x}")
        console.print(gtab)

    if offsets:
        otab = Table(title="Overflow offsets computed from the assembly")
        otab.add_column("Sink", style="bold red")
        otab.add_column("Function")
        otab.add_column("-> saved RBP")
        otab.add_column("-> saved RIP", style="bold green")
        otab.add_column("Conf.")
        for o in offsets:
            rbp_cell = (
                "n/a" if o.offset_to_saved_rbp < 0
                else f"{o.offset_to_saved_rbp} ({o.offset_to_saved_rbp:#x})"
            )
            otab.add_row(
                f"{o.sink} @ {o.call_address:#x}",
                o.in_function,
                rbp_cell,
                f"{o.offset_to_ret} ({o.offset_to_ret:#x}) [{o.frame_kind}]",
                o.confidence,
            )
        console.print(otab)
        if mitigations and mitigations.canary:
            console.print(
                "[yellow]canary enabled:[/] leak and keep the 8 bytes at rbp-8 "
                f"(buf+{offsets[0].offset_to_canary}) before overwriting RIP"
            )

    if not findings:
        console.print("[green]No sink calls found.[/]")
    else:
        _taint_style = {"tainted": "bold red", "local": "yellow", "constant": "dim"}
        table = Table(title="Suspicious call sites (verify each: expect false positives)")
        table.add_column("#", justify="right")
        table.add_column("Sev", justify="right")
        table.add_column("Sink", style="bold red")
        table.add_column("Bug class")
        table.add_column("Taint")
        table.add_column("Location")
        for i, f in enumerate(findings, start=1):
            taint = f.taint or "-"
            tstyle = _taint_style.get(f.taint or "", "")
            table.add_row(
                str(i),
                str(f.severity),
                f.sink.name,
                f.bug_class,
                f"[{tstyle}]{taint}[/]" if tstyle else taint,
                f.location,
            )
        console.print(table)

    if techniques:
        _conf_style = {"high": "bold red", "medium": "yellow", "low": "dim"}
        tech = Table(title="Candidate techniques to investigate (advisory)")
        tech.add_column("Technique", style="bold")
        tech.add_column("Conf.")
        tech.add_column("Have / need")
        tech.add_column("Gate")
        for t in techniques:
            style = _conf_style.get(t.confidence, "")
            if t.present or t.missing:
                pieces = f"[green]{len(t.present)}[/] have / [red]{len(t.missing)}[/] need"
            else:
                pieces = "-"
            tech.add_row(t.name, f"[{style}]{t.confidence}[/]", pieces, t.gate)
        console.print(tech)

    if gadgets is not None:
        if gadgets.gadgets:
            gtab = Table(
                title=f"ROP gadgets via {gadgets.tool} "
                f"({gadgets.total_scanned} scanned, read only)"
            )
            gtab.add_column("Gadget", style="bold magenta")
            gtab.add_column("Address")
            for label, addr in gadgets.gadgets.items():
                gtab.add_row(label, f"{addr:#x}")
            console.print(gtab)
        else:
            console.print(f"[dim]No curated gadgets. {gadgets.note}[/]")

    if indirect:
        itab = Table(title="Indirect dispatch points (unresolved targets)")
        itab.add_column("Address", style="bold")
        itab.add_column("Function")
        itab.add_column("Instruction", style="magenta")
        for ic in indirect:
            itab.add_row(f"{ic.address:#x}", ic.in_function, f"{ic.mnemonic} {ic.operand}")
        console.print(itab)

    if reachability is not None:
        if not reachability.available:
            console.print(f"[dim]reachability (angr): {reachability.note}[/]")
        elif reachability.reachable:
            rtab = Table(title="Static reachability from entry (angr)")
            rtab.add_column("Address", style="bold")
            rtab.add_column("Reachable")
            for addr, ok in reachability.reachable.items():
                mark = "[green]yes[/]" if ok else "[red]no[/]"
                rtab.add_row(f"{addr:#x}", mark)
            console.print(rtab)
        elif reachability.note:
            console.print(f"[dim]reachability (angr): {reachability.note}[/]")

    if onegadget is not None:
        if onegadget.gadgets:
            otab = Table(title=f"libc one_gadget candidates in {onegadget.libc} (read only)")
            otab.add_column("Offset", style="bold green")
            otab.add_column("Call")
            otab.add_column("Constraints")
            for g in onegadget.gadgets:
                otab.add_row(f"{g.offset:#x}", g.call, "\n".join(g.constraints) or "-")
            console.print(otab)
        elif onegadget.offsets:
            otab = Table(title=f"libc one_gadget offsets in {onegadget.libc} (read only)")
            otab.add_column("Offset", style="bold green")
            for off in onegadget.offsets:
                otab.add_row(f"{off:#x}")
            console.print(otab)
        else:
            console.print(f"[dim]No one_gadget offsets. {onegadget.note}[/]")
