"""Command line interface for Pwnariadne.

    pwnariadne BINARY [--source PATH ...] [--gdb OUT.gdb]
                      [--debugger pwndbg|gef|gdb|auto] [--gadgets]
                      [--format terminal|endpoints|markdown|json] [--output FILE]

Defensive and educational use only. Analyse binaries you are authorised to test.
"""

from __future__ import annotations

import argparse
import sys

from pwnariadne import SIGNATURE, __version__
from pwnariadne.classify import finding as finding_mod
from pwnariadne.core.elf import Binary, Mitigations
from pwnariadne.gdbgen import generator
from pwnariadne.integrations import DebuggerFlavor, detect_debugger, detect_toolbox
from pwnariadne.integrations.gadgets import GadgetResult, enumerate_gadgets
from pwnariadne.integrations.libc import (
    ChecksecResult,
    OneGadgetResult,
    find_one_gadgets,
    pwntools_checksec,
)
from pwnariadne.report import reporter
from pwnariadne.techniques import infer_techniques
from pwnariadne.techniques.analyze import Signals

_LOGO = r"""
  ____                           _           _
 |  _ \__      ___ __   __ _ _ _(_) __ _  __| |_ __   ___
 | |_) \ \ /\ / / '_ \ / _` | '__| |/ _` |/ _` | '_ \ / _ \
 |  __/ \ V  V /| | | | (_| | |  | | (_| | (_| | | | |  __/
 |_|     \_/\_/ |_| |_|\__,_|_|  |_|\__,_|\__,_|_| |_|\___|
"""

_TAGLINE = "the thread through the binary labyrinth"


def _print_banner() -> None:
    """Print the coloured banner, falling back to plain text if rich is absent."""

    try:
        from rich.console import Console

        c = Console(stderr=True)
        c.print(f"[bold red]{_LOGO}[/]")
        c.print(f" [bold cyan]Pwnariadne {__version__}[/]  [dim]{_TAGLINE}[/]")
        c.print(f" [yellow]{SIGNATURE}[/]\n")
    except Exception:  # noqa: BLE001 - the banner must never break the run
        print(_LOGO, file=sys.stderr)
        print(f" Pwnariadne {__version__}  {_TAGLINE}", file=sys.stderr)
        print(f" {SIGNATURE}\n", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwnariadne",
        description="Review a Linux binary for memory unsafe call sites, infer "
        "candidate techniques, and generate an observe only debugger script "
        "(pwndbg / GEF / gdb). Authorised and educational use only.",
        epilog=f"Author: {SIGNATURE}",
    )
    p.add_argument("binary", nargs="?", help="path to the ELF binary to analyse")
    p.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="PATH",
        help="C source file or directory to also scan (repeatable)",
    )
    p.add_argument(
        "--source-backend",
        choices=("auto", "treesitter", "regex"),
        default="auto",
        help="C source backend: tree-sitter (accurate) or regex (no deps). "
        "Default auto, preferring tree-sitter when installed",
    )
    p.add_argument(
        "--gdb",
        metavar="OUT.gdb",
        help="write a debugger breakpoint script to this path",
    )
    p.add_argument(
        "--debugger",
        choices=("auto", "pwndbg", "gef", "gdb"),
        default="auto",
        help="debugger front end the script targets (default: auto detect, "
        "preferring pwndbg)",
    )
    p.add_argument(
        "--gadgets",
        action="store_true",
        help="enumerate useful ROP gadgets via ROPgadget/ropper (read only)",
    )
    p.add_argument(
        "--libc",
        metavar="LIBC.so",
        help="enumerate libc one_gadget offsets from this libc (read only)",
    )
    p.add_argument(
        "--checksec",
        action="store_true",
        help="add a pwntools checksec cross check (if pwntools is installed)",
    )
    p.add_argument(
        "--indirect",
        action="store_true",
        help="list indirect dispatch points (function pointer / vtable / GOT calls)",
    )
    p.add_argument(
        "--toolbox",
        action="store_true",
        help="print which external tools were detected, then continue",
    )
    p.add_argument(
        "--format",
        choices=("terminal", "endpoints", "markdown", "json"),
        default="terminal",
        help="report format: terminal table, 'endpoints' (just the trigger "
        "points, one per line), markdown, or json (default: terminal)",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of stdout",
    )
    p.add_argument(
        "--no-techniques",
        action="store_true",
        help="do not print the advisory 'candidate techniques' section",
    )
    p.add_argument(
        "--no-banner", action="store_true", help="suppress the ASCII banner"
    )
    p.add_argument("--version", action="version", version=f"pwnariadne {__version__}")
    return p


def _resolve_flavor(choice: str) -> DebuggerFlavor:
    if choice == "auto":
        return detect_debugger()
    return DebuggerFlavor(choice)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.no_banner and args.format == "terminal":
        _print_banner()

    if args.toolbox:
        reporter.print_toolbox(detect_toolbox())

    if not args.binary and not args.source:
        print("error: provide a BINARY and/or --source PATH", file=sys.stderr)
        return 2

    findings = []
    mitigations: Mitigations | None = None
    signals = Signals()
    indirect = None

    if args.binary:
        try:
            with Binary(args.binary) as binary:
                mitigations = binary.mitigations()
                findings.extend(finding_mod.from_call_sites(binary.call_sites()))
                signals = Signals(
                    win_symbols=binary.win_symbols(),
                    imports=binary.imported_functions(),
                    strings=binary.interesting_strings(),
                )
                if args.indirect:
                    indirect = binary.indirect_call_sites()
                    if args.format == "terminal" and not args.no_banner:
                        print(
                            f"[pwnariadne] {binary.architecture_note()}",
                            file=sys.stderr,
                        )
        except FileNotFoundError:
            print(f"error: no such file: {args.binary}", file=sys.stderr)
            return 2
        except Exception as exc:  # noqa: BLE001 - surface any ELF parse failure
            print(f"error: could not analyse {args.binary}: {exc}", file=sys.stderr)
            return 1

    if args.source:
        from pwnariadne.review.source import active_backend, review_source

        findings.extend(review_source(args.source, backend=args.source_backend))
        if args.format == "terminal" and not args.no_banner:
            print(
                f"[pwnariadne] source backend: {active_backend(args.source_backend)}",
                file=sys.stderr,
            )

    _taint_rank = {"tainted": 2, "local": 1, "constant": 0}
    findings.sort(
        key=lambda f: (f.severity, _taint_rank.get(f.taint or "", 0)),
        reverse=True,
    )

    techniques = (
        []
        if args.no_techniques
        else infer_techniques(mitigations, findings, signals)
    )

    gadgets: GadgetResult | None = None
    if args.gadgets and args.binary:
        gadgets = enumerate_gadgets(args.binary)

    onegadget: OneGadgetResult | None = None
    if args.libc:
        onegadget = find_one_gadgets(args.libc)

    checksec: ChecksecResult | None = None
    if args.checksec and args.binary:
        checksec = pwntools_checksec(args.binary)

    _emit_report(
        args, findings, mitigations, techniques, gadgets, onegadget, checksec, indirect
    )

    if args.gdb:
        flavor = _resolve_flavor(args.debugger)
        script = generator.generate(findings, target=args.binary, flavor=flavor)
        with open(args.gdb, "w") as fh:
            fh.write(script)
        print(
            f"[pwnariadne] {flavor} script written to {args.gdb}", file=sys.stderr
        )

    return 0


def _emit_report(
    args, findings, mitigations, techniques, gadgets, onegadget, checksec, indirect
) -> None:
    if args.format == "endpoints":
        text = reporter.to_endpoints(findings)
    elif args.format == "json":
        text = reporter.to_json(
            findings, mitigations, techniques, gadgets, onegadget, checksec, indirect
        )
    elif args.format == "markdown":
        text = reporter.to_markdown(
            findings, mitigations, techniques, gadgets, onegadget, checksec, indirect
        )
    else:
        if args.output:
            from rich.console import Console

            with open(args.output, "w") as fh:
                reporter.to_terminal(
                    findings,
                    mitigations,
                    Console(file=fh),
                    techniques,
                    gadgets,
                    onegadget,
                    checksec,
                    indirect,
                )
            return
        reporter.to_terminal(
            findings,
            mitigations,
            techniques=techniques,
            gadgets=gadgets,
            onegadget=onegadget,
            checksec=checksec,
            indirect=indirect,
        )
        return

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
    else:
        print(text)


if __name__ == "__main__":
    raise SystemExit(main())
