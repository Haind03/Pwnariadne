"""Findings: a classified, ranked view over call sites and source hits."""

from __future__ import annotations

from dataclasses import dataclass

from pwnariadne.core.elf import CallSite
from pwnariadne.review.sinks import Sink, lookup


@dataclass
class Finding:
    """One suspicious location, ready for the report and the GDB script."""

    sink: Sink
    # Exactly one of (address) or (source_file, line) is meaningful.
    address: int | None
    in_function: str
    source_file: str | None = None
    line: int | None = None
    snippet: str | None = None

    @property
    def bug_class(self) -> str:
        return self.sink.bug_class

    @property
    def severity(self) -> int:
        return self.sink.severity

    @property
    def location(self) -> str:
        if self.address is not None:
            return f"{self.in_function} @ {self.address:#x}"
        if self.source_file is not None:
            return f"{self.source_file}:{self.line}"
        return "?"


def from_call_sites(sites: list[CallSite]) -> list[Finding]:
    """Map resolved PLT call sites to classified findings."""

    findings: list[Finding] = []
    for site in sites:
        sink = lookup(site.target_symbol)
        if sink is None:
            continue
        findings.append(
            Finding(
                sink=sink,
                address=site.address,
                in_function=site.in_function,
            )
        )
    return _rank(findings)


def _rank(findings: list[Finding]) -> list[Finding]:
    """Highest severity first; stable within equal severity."""

    return sorted(findings, key=lambda f: f.severity, reverse=True)
