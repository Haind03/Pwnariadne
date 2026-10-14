from pwnariadne.core.elf import Mitigations
from pwnariadne.techniques.hint import Signals
from pwnariadne.techniques.rop import analyze_rop


def _mit(**kw):
    base = dict(arch="x64", bits=64, relro="partial", canary=False, nx=True, pie=False)
    base.update(kw)
    return Mitigations(**base)


def _names(hints):
    return {h.name for h in hints}


def test_seccomp_adds_orw_and_suppresses_ret2system():
    sig = Signals(imports={"system"}, strings=["/bin/sh"], seccomp=True)
    names = _names(analyze_rop(_mit(), sig, {"pop rdi ; ret": 0x1}))
    assert "ORW chain (seccomp present)" in names
    # With a seccomp filter, ret2system is not offered (execve likely blocked).
    assert "ret2system" not in names


def test_no_seccomp_keeps_ret2system():
    sig = Signals(imports={"system"}, strings=["/bin/sh"], seccomp=False)
    names = _names(analyze_rop(_mit(), sig, {"pop rdi ; ret": 0x1}))
    assert "ORW chain (seccomp present)" not in names
    assert "ret2system" in names
