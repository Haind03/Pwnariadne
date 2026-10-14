from pwnariadne.core.elf import Mitigations
from pwnariadne.classify.finding import Finding
from pwnariadne.review.sinks import lookup
from pwnariadne.techniques import infer_techniques
from pwnariadne.techniques.hint import Signals


def _mit(**kw):
    base = dict(arch="x64", bits=64, relro="partial", canary=False, nx=True, pie=False)
    base.update(kw)
    return Mitigations(**base)


def _ret2win(hints):
    return next((h for h in hints if h.name == "ret2win"), None)


def _of():
    return [Finding(sink=lookup("gets"), address=0x1, in_function="vuln")]


def test_ret2win_shows_concrete_address_no_pie():
    sig = Signals(win_symbols=["win"], win_addrs={"win": 0x401176})
    h = _ret2win(infer_techniques(_mit(pie=False), _of(), sig))
    assert h is not None
    assert "win @ 0x401176" in h.present
    assert h.missing == []
    assert "p64(address)" in h.gate


def test_ret2win_pie_needs_base_leak():
    sig = Signals(win_symbols=["win"], win_addrs={"win": 0x1176})
    h = _ret2win(infer_techniques(_mit(pie=True), _of(), sig))
    assert h is not None
    assert "a text base leak" in h.missing
