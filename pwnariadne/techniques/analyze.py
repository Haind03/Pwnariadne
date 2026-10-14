"""Reason from mitigations + findings + signals to candidate techniques.

Each :class:`TechniqueHint` says: here is a technique class, here is why the
observed state makes it relevant, and here is the mitigation condition that
enables or blocks it. Nothing here produces an exploit: it is a study map.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pwnariadne.classify.finding import Finding
from pwnariadne.core.elf import Mitigations


@dataclass
class Signals:
    """Extra binary observations that steer technique inference."""

    win_symbols: list[str] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)
    strings: list[str] = field(default_factory=list)


@dataclass
class TechniqueHint:
    """One technique class worth investigating, with its rationale and gate."""

    name: str
    relevance: str  # why the observed state makes this relevant
    gate: str  # the mitigation condition that enables/blocks it
    confidence: str  # "high" | "medium" | "low"
    references: list[str] = field(default_factory=list)


def infer_techniques(
    mitigations: Mitigations | None,
    findings: list[Finding],
    signals: Signals | None = None,
) -> list[TechniqueHint]:
    """Produce an ordered list of advisory technique hints."""

    signals = signals or Signals()
    bug_classes = {f.bug_class for f in findings}
    hints: list[TechniqueHint] = []

    has_stack_of = "stack-buffer-overflow" in bug_classes or "buffer-overflow" in bug_classes
    has_fmt = "format-string" in bug_classes
    has_heap = any(
        c in bug_classes
        for c in ("use-after-free / double-free", "heap-overflow")
    )
    m = mitigations

    # --- control-flow hijack prerequisites --------------------------------
    if has_stack_of and m is not None:
        if not m.canary:
            hints.append(
                TechniqueHint(
                    name="saved-return-address overwrite",
                    relevance="A stack write primitive with no stack canary lets the "
                    "saved return address be reached directly.",
                    gate="canary=False (no leak step required)",
                    confidence="high",
                    references=["https://ctf101.org/binary-exploitation/stack-smashing/"],
                )
            )
        else:
            hints.append(
                TechniqueHint(
                    name="canary leak then overwrite",
                    relevance="A stack write primitive exists, but a stack canary must "
                    "be leaked (e.g. via a format-string read) before the return "
                    "address can be overwritten.",
                    gate="canary=True (needs an info-leak primitive first)",
                    confidence="medium" if has_fmt else "low",
                )
            )

    # --- what to do once control flow is hijackable -----------------------
    if has_stack_of and m is not None:
        if not m.nx:
            hints.append(
                TechniqueHint(
                    name="ret2shellcode (NX off)",
                    relevance="Writable+executable memory (NX disabled) means injected "
                    "code in a buffer can be executed.",
                    gate="nx=False",
                    confidence="high",
                )
            )
        else:
            hints.append(
                TechniqueHint(
                    name="ROP / ret2libc (NX on)",
                    relevance="NX blocks injected code, so code-reuse (ROP gadgets or a "
                    "libc call chain) is the path to study.",
                    gate="nx=True" + ("; no PIE eases fixed gadget addresses" if not m.pie else "; PIE needs a base leak"),
                    confidence="high",
                    references=["https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming"],
                )
            )
        if signals.win_symbols:
            hints.append(
                TechniqueHint(
                    name="ret2win",
                    relevance="A win/backdoor-looking function is defined: "
                    + ", ".join(signals.win_symbols[:5]),
                    gate="redirect the return address to this function"
                    + ("" if not m.pie else " (PIE: needs a base leak)"),
                    confidence="high",
                )
            )
        if "system" in signals.imports and any(
            "sh" in s for s in signals.strings
        ):
            hints.append(
                TechniqueHint(
                    name="ret2system / one-gadget territory",
                    relevance="system() is imported and a shell string is present in "
                    "the binary.",
                    gate="reach system() with the shell string as its argument",
                    confidence="medium",
                )
            )

    # --- format-string primitives -----------------------------------------
    if has_fmt:
        hints.append(
            TechniqueHint(
                name="format-string read (leak)",
                relevance="A user-controlled format string yields an arbitrary memory "
                "read, usable to leak a canary, a stack/PIE/libc address.",
                gate="works regardless of NX/canary; defeats ASLR via leak",
                confidence="high",
                references=["https://ctf101.org/binary-exploitation/what-is-the-stack/"],
            )
        )
        if m is not None and m.relro != "full":
            hints.append(
                TechniqueHint(
                    name="GOT overwrite (format-string write)",
                    relevance="A format-string %n write combined with a non-full RELRO "
                    "(writable GOT) can redirect a resolved function.",
                    gate=f"relro={m.relro} (GOT writable)",
                    confidence="high" if m.relro == "none" else "medium",
                )
            )
        elif m is not None:
            hints.append(
                TechniqueHint(
                    name="format-string write (GOT blocked)",
                    relevance="A %n write primitive exists, but Full RELRO makes the GOT "
                    "read-only: target writable function pointers / saved state instead.",
                    gate="relro=full (GOT read-only)",
                    confidence="low",
                )
            )

    # --- heap -------------------------------------------------------------
    if has_heap:
        hints.append(
            TechniqueHint(
                name="heap: UAF / double-free / tcache study",
                relevance="Heap allocation and free calls are present; investigate "
                "use-after-free, double-free and tcache/fastbin integrity.",
                gate="depends on allocator version and freed-chunk reuse",
                confidence="medium",
                references=["https://heap-exploitation.dhavalkapil.com/"],
            )
        )

    return hints
