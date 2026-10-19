"""Deeper heap-exploitation reasoning.

From the heap related findings (malloc / free / use-after-free / heap overflow)
this enumerates the glibc ptmalloc techniques worth studying, each with the
primitive it needs and the allocator versions where it applies. It is a study
map: it assembles no primitive and writes no payload.
"""

from __future__ import annotations

from pwnariadne.classify.finding import Finding
from pwnariadne.techniques.hint import TechniqueHint

_HEAP_REF = "https://heap-exploitation.dhavalkapil.com/"


def analyze_heap(findings: list[Finding], signals) -> list[TechniqueHint]:
    """Return heap sub-technique hints based on the heap findings."""

    frees = [f for f in findings if f.sink.name == "free"]
    mallocs = [f for f in findings if f.sink.name in ("malloc", "calloc", "realloc")]
    uaf = [f for f in findings if "use-after-free" in f.bug_class]
    heap_of = [f for f in findings if f.bug_class == "heap-overflow"]

    hints: list[TechniqueHint] = []
    if not (frees or mallocs or uaf or heap_of):
        return hints

    # Use-after-free: dangling pointer reused.
    if uaf:
        hints.append(
            TechniqueHint(
                name="heap: use-after-free (UAF)",
                relevance="A freed chunk is still reachable through a dangling pointer; "
                "reallocating it lets attacker data land on a live object (type "
                "confusion, overwritten function pointer).",
                gate="needs allocation of the victim size between free and use",
                confidence="high",
                present=["free then later use of the same pointer"],
                missing=["a same-size allocation you control between free and use"],
                references=[_HEAP_REF + "attacks/first_fit.html"],
            )
        )

    # Double free -> tcache / fastbin dup.
    if len(frees) >= 2:
        hints.append(
            TechniqueHint(
                name="heap: double-free -> tcache/fastbin poisoning",
                relevance="Freeing a chunk twice puts it on the bin list twice; a later "
                "malloc returns it while it is still linked, letting you overwrite the "
                "fd pointer and get an arbitrary-address allocation (tcache poisoning).",
                gate="glibc < 2.29 (no tcache key); 2.29+ needs a key bypass first",
                confidence="medium",
                present=[f"{len(frees)} free call sites"],
                missing=["a write into the freed chunk's fd", "the target glibc version"],
                references=[_HEAP_REF + "attacks/double_free.html"],
            )
        )

    # Heap overflow -> chunk metadata corruption.
    if heap_of:
        hints.append(
            TechniqueHint(
                name="heap: overflow into chunk metadata",
                relevance="An overflow past a chunk corrupts the next chunk's size/flags "
                "or a freed chunk's fd/bk, enabling tcache poisoning, unlink, or house-"
                "of-* primitives.",
                gate="needs adjacent controlled chunks and a known heap layout",
                confidence="medium",
                present=["heap overflow write"],
                missing=["heap grooming to place the victim chunk"],
                references=[_HEAP_REF + "attacks/unlink_exploit.html"],
            )
        )

    # tcache poisoning is the modern go-to when UAF or overflow + alloc exist.
    if (uaf or heap_of) and mallocs:
        hints.append(
            TechniqueHint(
                name="heap: tcache poisoning (arbitrary alloc)",
                relevance="Overwrite a freed tcache chunk's fd with a target address; the "
                "second malloc of that size then returns the target for an arbitrary "
                "write (e.g. __free_hook, a GOT entry, a stack return address).",
                gate="glibc 2.26+; 2.32+ safe-linking mangles fd (fd = (addr>>12) ^ ptr), "
                "so a heap-base leak is needed; 2.34+ lost the hooks, retarget "
                "__free_hook-style writes to _IO_FILE / exit handlers",
                confidence="medium",
                present=["a freed-chunk write primitive", "attacker-driven malloc"],
                missing=["a target address", "on 2.32+ a heap leak to defeat safe-linking"],
                references=[_HEAP_REF + "attacks/first_fit.html"],
            )
        )

    # Unsorted-bin leak for a libc address.
    if frees and mallocs:
        hints.append(
            TechniqueHint(
                name="heap: unsorted-bin libc leak",
                relevance="A freed large chunk keeps main_arena (libc) pointers in its "
                "fd/bk; reading it back leaks a libc address to defeat ASLR.",
                gate="chunk too big for tcache/fastbin so it lands in the unsorted bin",
                confidence="medium",
                present=["free then read-back of a large chunk"],
                missing=["a read of the freed chunk's first 16 bytes"],
                references=[_HEAP_REF + "diving_into_glibc_heap/"],
            )
        )

    hints.extend(_house_of_x(frees, mallocs, uaf, heap_of, signals))
    return hints


# Functions whose presence shows the binary uses stdio (needed for FSOP).
_STDIO = {
    "printf", "puts", "fwrite", "fread", "fopen", "fclose", "setbuf",
    "setvbuf", "fflush", "__isoc99_scanf", "scanf", "fgets",
}


def _house_of_x(frees, mallocs, uaf, heap_of, signals) -> list[TechniqueHint]:
    """Advanced allocator-abuse techniques (house-of-* family and FSOP)."""

    out: list[TechniqueHint] = []
    imports = getattr(signals, "imports", set()) or set()

    # House of Force: overwrite the top chunk size to an attacker value.
    if heap_of:
        out.append(
            TechniqueHint(
                name="heap: House of Force",
                relevance="Overflowing into the top chunk's size field lets a crafted "
                "malloc move the top pointer to an arbitrary address for a write.",
                gate="glibc < 2.30 (top-size check added in 2.30 removes this)",
                confidence="low",
                present=["overflow reaching the top chunk size"],
                missing=["an attacker-controlled malloc size", "a target address"],
                references=["https://github.com/shellphish/how2heap"],
            )
        )

    # House of Spirit: free a fake chunk you control, then reallocate it.
    if frees and (heap_of or uaf):
        out.append(
            TechniqueHint(
                name="heap: House of Spirit",
                relevance="Free a forged chunk located in attacker-controlled memory "
                "(stack/bss); the next malloc of that size hands the region back.",
                gate="needs a fake chunk with valid size and a free of its pointer",
                confidence="low",
                present=["a free of an attacker-influenced pointer"],
                missing=["a forged chunk header (size, alignment)"],
                references=["https://github.com/shellphish/how2heap"],
            )
        )

    # FSOP / House of Orange: hijack the _IO_FILE vtable.
    if (uaf or heap_of or len(frees) >= 2) and (imports & _STDIO):
        out.append(
            TechniqueHint(
                name="heap: FSOP / _IO_FILE vtable hijack",
                relevance="The binary uses stdio; corrupting an _IO_FILE structure (or "
                "_IO_list_all) and its vtable turns the next stdio call into controlled "
                "execution. House of Orange reaches this from an unsorted-bin overlap.",
                gate="2.24+ adds vtable checks (use _IO_str_jumps); 2.34+ removed the "
                "malloc/free hooks, so FSOP (House of Apple 2, _IO_list_all) is the "
                "modern path",
                confidence="low",
                present=["heap corruption primitive", "stdio in use"],
                missing=["an _IO_FILE overwrite path", "the libc base (leak first)"],
                references=["https://github.com/shellphish/how2heap",
                            "https://bbs.kanxue.com/thread-273832.htm"],
            )
        )

    # Large bin attack: write a controlled value via large-bin insertion.
    if frees and mallocs:
        out.append(
            TechniqueHint(
                name="heap: large bin attack",
                relevance="Corrupting a large-bin chunk's bk_nextsize writes a heap/libc "
                "pointer (or controlled value) to a chosen address during insertion.",
                gate="glibc 2.23-2.29 class of attacks; a known target to overwrite",
                confidence="low",
                present=["free/alloc of large (> 0x400) chunks"],
                missing=["a write into a freed large-bin chunk", "a target pointer"],
                references=["https://github.com/shellphish/how2heap"],
            )
        )

    return out
