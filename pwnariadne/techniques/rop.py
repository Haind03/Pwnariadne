"""Deeper ROP-chain reasoning.

Given the mitigations, the binary signals and the curated gadget set, this
enumerates the ROP sub-techniques worth studying and, for each, which building
blocks are already present and which are still missing. It assembles no chain
and writes no payload: it only maps what the binary makes possible.
"""

from __future__ import annotations

from pwnariadne.techniques.hint import TechniqueHint

# Gadget labels Pwnariadne curates (see integrations/gadgets.py).
_ARG_GADGETS = ("pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rax ; ret")


def analyze_rop(
    m,
    signals,
    gadgets: dict[str, int] | None,
) -> list[TechniqueHint]:
    """Return ROP sub-technique hints. ``m`` is Mitigations (NX assumed on)."""

    gadgets = gadgets or {}
    have = set(gadgets)
    hints: list[TechniqueHint] = []
    pie_note = "" if (m and not m.pie) else " (PIE: needs a text/libc base leak first)"

    # Which argument-setup gadgets are in the binary itself.
    present_args = [g for g in _ARG_GADGETS if g in have]
    missing_args = [g for g in _ARG_GADGETS if g not in have]

    # --- classic ret2libc / call-oriented chain ---------------------------
    hints.append(
        TechniqueHint(
            name="ret2libc chain",
            relevance="Set the argument registers with pop gadgets, then return into "
            "a libc function (system, execve) or a PLT entry.",
            gate=f"nx=on{pie_note}",
            confidence="high" if "pop rdi ; ret" in have else "medium",
            present=present_args + (["ret (stack align)"] if "ret" in have else []),
            missing=missing_args
            + ([] if "pop rdi ; ret" in have else ["a pop rdi ; ret to set arg0"]),
            references=["https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2libc"],
        )
    )

    # --- ret2system (concrete, pieces checked) ----------------------------
    has_system = "system" in signals.imports
    has_sh = any("sh" in s for s in signals.strings)
    if has_system or has_sh:
        present = []
        missing = []
        present.append("system() imported") if has_system else missing.append("a system()/execve call target")
        present.append('"/bin/sh" string') if has_sh else missing.append('a "/bin/sh" string (or write one)')
        present.append("pop rdi ; ret") if "pop rdi ; ret" in have else missing.append("pop rdi ; ret for arg0")
        hints.append(
            TechniqueHint(
                name="ret2system",
                relevance="Call system(\"/bin/sh\") by chaining a pop rdi ; ret into "
                "system with the shell string as its argument.",
                gate=f"nx=on{pie_note}",
                confidence="high" if (has_system and has_sh and "pop rdi ; ret" in have) else "medium",
                present=present,
                missing=missing,
            )
        )

    # --- ret2csu: universal gadget when pop gadgets are scarce -------------
    csu = "__libc_csu_init" in signals.funcs or "__libc_csu_init" in signals.imports
    if csu and not ("pop rdi ; ret" in have and "pop rsi ; ret" in have):
        hints.append(
            TechniqueHint(
                name="ret2csu",
                relevance="__libc_csu_init is present; its two gadgets set rbx/rbp/r12-r15 "
                "and can populate rdi/rsi/rdx when single pop gadgets are missing.",
                gate="nx=on; useful on non-PIE or after a base leak",
                confidence="medium",
                present=["__libc_csu_init"],
                missing=[g for g in ("pop rsi ; ret", "pop rdx ; ret") if g not in have],
                references=["https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2csu"],
            )
        )

    # --- stack pivot for short overflows ----------------------------------
    pivots = [g for g in ("leave ; ret", "pop rsp ; ret") if g in have]
    if pivots:
        hints.append(
            TechniqueHint(
                name="stack pivot",
                relevance="A limited overflow can be extended by pivoting the stack into "
                "a buffer you control, then running the real chain there.",
                gate="needs a writable, known/leakable region to pivot into",
                confidence="medium",
                present=pivots,
                missing=["a controlled fake stack (bss/heap) address"],
                references=["https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting"],
            )
        )

    # --- direct syscalls / SROP (common on static binaries) ---------------
    if "syscall" in have or "int 0x80" in have:
        srop_present = [g for g in ("syscall", "int 0x80", "pop rax ; ret") if g in have]
        hints.append(
            TechniqueHint(
                name="syscall ROP / SROP",
                relevance="A syscall gadget lets you invoke execve directly, or forge a "
                "sigreturn frame (SROP) to set every register at once.",
                gate="static or syscall-reachable binary; SROP needs rax=15 then syscall",
                confidence="high" if signals.is_static else "medium",
                present=srop_present,
                missing=[] if "pop rax ; ret" in have else ["pop rax ; ret to control the syscall number"],
                references=["https://ir0nstone.gitbook.io/notes/types/stack/syscalls/srop"],
            )
        )

    # --- ret2dlresolve when there is no leak path -------------------------
    no_leak = not any("sh" in s for s in signals.strings) and not signals.is_static
    if m and m.relro != "full" and no_leak and not has_system:
        hints.append(
            TechniqueHint(
                name="ret2dlresolve",
                relevance="With a writable GOT/.dynamic and no libc leak available, forge "
                "a Elf symbol resolution to call an arbitrary libc function.",
                gate=f"relro={m.relro} (resolver still writable); dynamic binary",
                confidence="low",
                present=["dynamic binary", f"relro={m.relro}"],
                missing=["a write primitive into .bss for the fake structures"],
                references=["https://ir0nstone.gitbook.io/notes/types/stack/exploitation/ret2dlresolve"],
            )
        )

    return hints
