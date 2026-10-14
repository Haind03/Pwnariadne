"""Reason from mitigations + findings + signals to candidate techniques.

Each :class:`TechniqueHint` says: here is a technique class, here is why the
observed state makes it relevant, and here is the mitigation condition that
enables or blocks it. Nothing here produces an exploit: it is a study map.
"""

from __future__ import annotations

from pwnariadne.classify.finding import Finding
from pwnariadne.core.elf import Mitigations
from pwnariadne.techniques.heap import analyze_heap
from pwnariadne.techniques.hint import Signals, TechniqueHint
from pwnariadne.techniques.rop import analyze_rop

__all__ = ["Signals", "TechniqueHint", "infer_techniques"]


def infer_techniques(
    mitigations: Mitigations | None,
    findings: list[Finding],
    signals: Signals | None = None,
    gadgets: dict[str, int] | None = None,
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
        if not m.nx or signals.rwx:
            why = ("NX is disabled" if not m.nx
                   else "a loadable segment is writable+executable (W^X off)")
            hints.append(
                TechniqueHint(
                    name="ret2shellcode",
                    relevance=f"{why}, so injected code in a known/leakable buffer can "
                    "be executed directly.",
                    gate="nx=False or an RWX region; you need its address",
                    confidence="high",
                    present=(["RWX segment"] if signals.rwx else ["NX disabled"]),
                )
            )
        if m.nx:
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
            if "mprotect" in signals.imports or "mmap" in signals.imports:
                hints.append(
                    TechniqueHint(
                        name="mprotect/mmap to RWX then shellcode",
                        relevance="mprotect/mmap is imported: a ROP chain can mark a "
                        "region RWX (or map one), copy shellcode in, and jump to it, "
                        "sidestepping NX without a full libc call chain.",
                        gate="nx=True but mprotect/mmap reachable",
                        confidence="medium",
                        present=[g for g in ("mprotect", "mmap") if g in signals.imports],
                        missing=["gadgets to set rdi/rsi/rdx for the mprotect call"],
                        references=["https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming"],
                    )
                )
        if signals.win_symbols:
            if signals.win_addrs and not m.pie:
                targets = [f"{n} @ {signals.win_addrs[n]:#x}"
                           for n in signals.win_symbols[:5] if n in signals.win_addrs]
                gate = ("no PIE: use the address directly as the saved RIP "
                        "(pad to offset_to_ret, then p64(address))")
            else:
                targets = list(signals.win_symbols[:5])
                gate = "PIE: the address is a file offset; add the leaked text base"
            hints.append(
                TechniqueHint(
                    name="ret2win",
                    relevance="A win/backdoor-looking function is defined.",
                    gate=gate,
                    confidence="high",
                    present=targets,
                    missing=[] if (signals.win_addrs and not m.pie) else ["a text base leak"],
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

    # --- ROP chain detail (NX on): concrete sub-techniques + gadgets ------
    if has_stack_of and m is not None and m.nx:
        hints.extend(analyze_rop(m, signals, gadgets))

    # --- heap sub-techniques ---------------------------------------------
    if has_heap:
        hints.extend(analyze_heap(findings, signals))

    return hints
