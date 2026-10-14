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
                gate="glibc 2.26+; 2.32+ mangles fd (needs a heap-base leak)",
                confidence="medium",
                present=["a freed-chunk write primitive", "attacker-driven malloc"],
                missing=["a target address", "on 2.32+ a heap leak to defeat fd mangling"],
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

    return hints
