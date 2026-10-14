"""Command-line interface for Pwnariadne.

    pwnariadne BINARY [--source PATH ...] [--gdb OUT.gdb]
                      [--format terminal|markdown|json] [--output FILE]

Defensive / educational use only. Analyse binaries you are authorised to test.
"""

from __future__ import annotations

import argparse
import sys

from pwnariadne import SIGNATURE, __version__
from pwnariadne.classify import finding as finding_mod
from pwnariadne.core.elf import Binary, Mitigations
from pwnariadne.gdbgen import generator
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

# A compact labyrinth-and-thread motif, in the spirit of the SVG logo.
_THREAD = "  ╔═╦═══╗  ·──●  follow the thread from input to crash"


def _print_banner() -> None:
    """Print the coloured banner, falling back to plain text if rich is absent."""

    try:
        from rich.console import Console

        c = Console(stderr=True)
        c.print(f"[bold red]{_LOGO}[/]")
        c.print(f"[dim]{_THREAD}[/]")
        c.print(
            f" [bold cyan]Pwnariadne {__version__}[/] "
            f"[dim]— the thread through the binary labyrinth[/]"
        )
        c.print(f" [yellow]{SIGNATURE}[/]\n")
    except Exception:  # noqa: BLE001 - banner must never break the run
        print(_LOGO, file=sys.stderr)
        print(f" Pwnariadne {__version__} — {SIGNATURE}\n", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwnariadne",
        description="Review a Linux binary for memory-unsafe call sites and "
        "generate an observe-only GDB script. Authorised/educational use only.",
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
        "--gdb",
        metavar="OUT.gdb",
        help="write a GDB breakpoint script to this path",
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.no_banner and args.format == "terminal":
        _print_banner()

    if not args.binary and not args.source:
        print("error: provide a BINARY and/or --source PATH", file=sys.stderr)
        return 2

    findings = []
    mitigations: Mitigations | None = None
    signals = Signals()

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
        except FileNotFoundError:
            print(f"error: no such file: {args.binary}", file=sys.stderr)
            return 2
        except Exception as exc:  # noqa: BLE001 - surface any ELF parse failure
            print(f"error: could not analyse {args.binary}: {exc}", file=sys.stderr)
            return 1

    if args.source:
        from pwnariadne.review.source import review_source

        findings.extend(review_source(args.source))

    findings.sort(key=lambda f: f.severity, reverse=True)

    techniques = (
        [] if args.no_techniques
        else infer_techniques(mitigations, findings, signals)
    )

    _emit_report(args, findings, mitigations, techniques)

    if args.gdb:
        script = generator.generate(findings, target=args.binary)
        with open(args.gdb, "w") as fh:
            fh.write(script)
        print(f"[pwnariadne] GDB script written to {args.gdb}", file=sys.stderr)

    return 0


def _emit_report(args, findings, mitigations, techniques) -> None:
    if args.format == "endpoints":
        text = reporter.to_endpoints(findings)
    elif args.format == "json":
        text = reporter.to_json(findings, mitigations, techniques)
    elif args.format == "markdown":
        text = reporter.to_markdown(findings, mitigations, techniques)
    else:
        if args.output:
            from rich.console import Console

            with open(args.output, "w") as fh:
                reporter.to_terminal(findings, mitigations, Console(file=fh), techniques)
            return
        reporter.to_terminal(findings, mitigations, techniques=techniques)
        return

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(text)
    else:
        print(text)


if __name__ == "__main__":
    raise SystemExit(main())
