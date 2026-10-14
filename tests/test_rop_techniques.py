from pwnariadne.core.elf import Mitigations
from pwnariadne.techniques.hint import Signals
from pwnariadne.techniques.rop import analyze_rop


def _mit(**kw):
    base = dict(arch="x64", bits=64, relro="partial", canary=False, nx=True, pie=False)
    base.update(kw)
    return Mitigations(**base)


def _names(hints):
    return {h.name for h in hints}


def _get(hints, name):
    return next(h for h in hints if h.name == name)


def test_ret2libc_chain_high_when_pop_rdi_present():
    hints = analyze_rop(_mit(), Signals(), {"pop rdi ; ret": 0x1, "ret": 0x2})
    chain = _get(hints, "ret2libc chain")
    assert chain.confidence == "high"
    assert "pop rdi ; ret" in chain.present


def test_ret2libc_chain_medium_without_pop_rdi():
    hints = analyze_rop(_mit(), Signals(), {})
    chain = _get(hints, "ret2libc chain")
    assert chain.confidence == "medium"
    assert any("pop rdi" in m for m in chain.missing)


def test_ret2system_high_when_all_pieces_present():
    sig = Signals(imports={"system"}, strings=["/bin/sh"])
    hints = analyze_rop(_mit(), sig, {"pop rdi ; ret": 0x1})
    r = _get(hints, "ret2system")
    assert r.confidence == "high"
    assert r.missing == []


def test_ret2system_medium_when_gadget_missing():
    sig = Signals(imports={"system"}, strings=["/bin/sh"])
    hints = analyze_rop(_mit(), sig, {})
    r = _get(hints, "ret2system")
    assert r.confidence == "medium"
    assert any("pop rdi" in m for m in r.missing)


def test_ret2csu_when_csu_present_and_pops_scarce():
    sig = Signals(funcs={"__libc_csu_init"})
    hints = analyze_rop(_mit(), sig, {})
    assert "ret2csu" in _names(hints)


def test_no_ret2csu_when_pop_gadgets_available():
    sig = Signals(funcs={"__libc_csu_init"})
    hints = analyze_rop(_mit(), sig, {"pop rdi ; ret": 0x1, "pop rsi ; ret": 0x2})
    assert "ret2csu" not in _names(hints)


def test_stack_pivot_on_leave_ret():
    hints = analyze_rop(_mit(), Signals(), {"leave ; ret": 0x1})
    assert "stack pivot" in _names(hints)


def test_srop_when_syscall_gadget_and_static():
    hints = analyze_rop(_mit(), Signals(is_static=True), {"syscall": 0x1})
    s = _get(hints, "syscall ROP / SROP")
    assert s.confidence == "high"
