"""Optional static reachability check powered by angr.

Given the addresses of sink call sites, this asks a simple question: starting
from the binary's entry point, can control flow reach the function that
contains each sink? It builds a fast CFG and walks the call graph; it does not
execute the binary and emits no input. It is a prioritisation aid: a sink in
dead or unreachable code matters less than one on a path from main.

angr is a heavy optional dependency. When it is not installed, every call
degrades to a clear note instead of an error, so the rest of the tool is
unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ReachResult:
    """Per-address reachability verdicts from the entry point."""

    available: bool
    reachable: dict[int, bool] = field(default_factory=dict)
    note: str = ""


def available() -> bool:
    """Return True if angr can be imported."""

    try:
        import angr  # noqa: F401
    except Exception:  # noqa: BLE001 - angr import is heavy and may fail
        return False
    return True


def reachable_sinks(
    binary_path: str, targets: list[int], timeout: int = 180
) -> ReachResult:
    """Return, for each target address, whether it is reachable from entry.

    ``targets`` are virtual addresses of sink call sites. The check is a call
    graph reachability test over a fast CFG, not symbolic execution, so it is
    quick but conservative (indirect calls may hide real edges).
    """

    if not targets:
        return ReachResult(available=True, note="no binary sink addresses to check")

    if not available():
        return ReachResult(
            available=False, note="angr not installed (pip install angr)"
        )

    try:
        import angr
        import networkx
    except Exception as exc:  # noqa: BLE001
        return ReachResult(available=False, note=f"angr import failed: {exc}")

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        functions = cfg.kb.functions

        entry_func = functions.floor_func(proj.entry)
        callgraph = functions.callgraph

        reachable_funcs: set[int] = set()
        if entry_func is not None and entry_func.addr in callgraph:
            reachable_funcs = {entry_func.addr}
            reachable_funcs |= set(
                networkx.descendants(callgraph, entry_func.addr)
            )

        verdicts: dict[int, bool] = {}
        for addr in targets:
            holder = functions.floor_func(addr)
            verdicts[addr] = bool(holder and holder.addr in reachable_funcs)

        return ReachResult(available=True, reachable=verdicts)
    except Exception as exc:  # noqa: BLE001 - surface any angr analysis failure
        return ReachResult(available=False, note=f"angr analysis failed: {exc}")
