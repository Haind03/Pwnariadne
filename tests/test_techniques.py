from pwnariadne.classify.finding import Finding
from pwnariadne.core.elf import Mitigations
from pwnariadne.review.sinks import lookup
from pwnariadne.techniques.analyze import Signals, infer_techniques


def _mit(**kw):
    base = dict(arch="x64", bits=64, relro="partial", canary=False, nx=True, pie=False)
    base.update(kw)
    return Mitigations(**base)


def _finding(sink_name):
    return Finding(sink=lookup(sink_name), address=0x1000, in_function="f")


def _names(hints):
    return {h.name for h in hints}


def test_no_canary_enables_direct_overwrite():
    hints = infer_techniques(_mit(canary=False), [_finding("gets")])
    assert "saved-return-address overwrite" in _names(hints)


def test_canary_requires_leak_first():
    hints = infer_techniques(_mit(canary=True), [_finding("gets")])
    assert "canary leak then overwrite" in _names(hints)
    assert "saved-return-address overwrite" not in _names(hints)


def test_nx_off_suggests_shellcode():
    hints = infer_techniques(_mit(nx=False), [_finding("gets")])
    assert "ret2shellcode" in _names(hints)


def test_nx_on_suggests_rop():
    hints = infer_techniques(_mit(nx=True), [_finding("gets")])
    assert "ROP / ret2libc (NX on)" in _names(hints)


def test_win_symbol_suggests_ret2win():
    sig = Signals(win_symbols=["win", "get_shell"])
    hints = infer_techniques(_mit(), [_finding("gets")], sig)
    assert "ret2win" in _names(hints)


def test_format_string_offers_leak_and_got_overwrite():
    hints = infer_techniques(_mit(relro="partial"), [_finding("printf")])
    assert "format-string read (leak)" in _names(hints)
    assert "GOT overwrite (format-string write)" in _names(hints)


def test_full_relro_blocks_got_overwrite():
    hints = infer_techniques(_mit(relro="full"), [_finding("printf")])
    names = _names(hints)
    assert "GOT overwrite (format-string write)" not in names
    assert "format-string write (GOT blocked)" in names


def test_heap_sinks_flagged():
    hints = infer_techniques(_mit(), [_finding("free"), _finding("malloc")])
    assert any("heap" in h.name for h in hints)


def test_no_mitigations_yields_fmt_only():
    # Without a binary (mitigations=None) only mitigation-independent hints appear.
    hints = infer_techniques(None, [_finding("printf")])
    assert "format-string read (leak)" in _names(hints)


def test_rwx_segment_suggests_shellcode_even_with_nx():
    from pwnariadne.techniques.hint import Signals
    hints = infer_techniques(_mit(nx=True), [_finding("gets")], Signals(rwx=True))
    assert "ret2shellcode" in _names(hints)


def test_mprotect_import_suggests_rwx_pivot():
    from pwnariadne.techniques.hint import Signals
    hints = infer_techniques(_mit(nx=True), [_finding("gets")], Signals(imports={"mprotect"}))
    assert any("mprotect" in h.name for h in hints)
