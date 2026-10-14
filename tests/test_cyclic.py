from pwnariadne.core.cyclic import cyclic, cyclic_find


def test_pattern_is_pwntools_compatible():
    assert cyclic(16) == b"aaaabaaacaaadaaa"


def test_find_round_trips():
    p = cyclic(200)
    for off in (0, 4, 40, 72, 100, 150):
        assert cyclic_find(p[off : off + 4]) == off


def test_find_accepts_little_endian_int():
    p = cyclic(100)
    sub = p[72:76]
    value = int.from_bytes(sub, "little")
    assert cyclic_find(value) == 72


def test_find_missing_returns_minus_one():
    assert cyclic_find(b"ZZZZ") == -1


def test_length_zero():
    assert cyclic(0) == b""
