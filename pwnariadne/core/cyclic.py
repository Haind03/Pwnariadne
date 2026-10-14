"""De Bruijn (cyclic) pattern helpers for verifying an overflow offset.

A cyclic pattern is a diagnostic sequence where every n-byte window is unique,
so the bytes that land in the saved RIP map back to exactly one position. This
is the standard way to confirm an offset: it carries no shellcode and no
addresses, it only locates where control is taken. Compatible with pwntools'
``cyclic`` (same default alphabet and n=4).
"""

from __future__ import annotations

from itertools import cycle, islice

_ALPHABET = b"abcdefghijklmnopqrstuvwxyz"


def _de_bruijn(alphabet: bytes, n: int):
    """Generate a De Bruijn sequence over ``alphabet`` with subsequences of n."""

    k = len(alphabet)
    a = [0] * (k * n)
    seq: list[int] = []

    def db(t: int, p: int):
        if t > n:
            if n % p == 0:
                seq.extend(a[1 : p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return (alphabet[i] for i in cycle(seq))


def cyclic(length: int, n: int = 4) -> bytes:
    """Return a cyclic pattern of ``length`` bytes (unique n-byte windows)."""

    if length < 0:
        raise ValueError("length must be non-negative")
    return bytes(islice(_de_bruijn(_ALPHABET, n), length))


def cyclic_find(sub, n: int = 4) -> int:
    """Return the offset of ``sub`` (bytes/int) in the cyclic pattern, or -1.

    ``sub`` may be the n bytes recovered from the saved RIP, or an integer whose
    little-endian low n bytes are used (e.g. a leaked register value).
    """

    if isinstance(sub, int):
        sub = sub.to_bytes((max(sub.bit_length(), 1) + 7) // 8 or 1, "little")
    sub = bytes(sub)[:n]
    if len(sub) < n:
        return -1
    # Generate a generous window and scan for the subsequence.
    space = len(_ALPHABET) ** n
    gen = _de_bruijn(_ALPHABET, n)
    window = bytes(islice(gen, n))
    if window == sub:
        return 0
    for idx in range(1, space):
        window = window[1:] + bytes(islice(gen, 1))
        if window == sub:
            return idx
    return -1
