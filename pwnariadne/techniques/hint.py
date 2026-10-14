"""Shared data types for technique inference (kept here to avoid import cycles)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Signals:
    """Extra binary observations that steer technique inference."""

    win_symbols: list[str] = field(default_factory=list)
    win_addrs: dict[str, int] = field(default_factory=dict)  # win symbol -> address
    imports: set[str] = field(default_factory=set)
    strings: list[str] = field(default_factory=list)
    funcs: set[str] = field(default_factory=set)  # defined function names
    is_static: bool = False  # statically linked (no dynamic imports)
    seccomp: bool = False  # binary installs a seccomp filter (execve likely blocked)
    rwx: bool = False  # a loadable segment is writable and executable (W^X off)


@dataclass
class TechniqueHint:
    """One technique class worth investigating, with its rationale and gate."""

    name: str
    relevance: str  # why the observed state makes this relevant
    gate: str  # the mitigation condition that enables/blocks it
    confidence: str  # "high" | "medium" | "low"
    references: list[str] = field(default_factory=list)
    present: list[str] = field(default_factory=list)  # pieces already available
    missing: list[str] = field(default_factory=list)  # pieces still needed
