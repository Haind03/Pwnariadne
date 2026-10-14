from pwnariadne.classify.finding import Finding
from pwnariadne.core.offsets import OverflowOffset
from pwnariadne.gdbgen.generator import generate, _constraint_to_gdb
from pwnariadne.integrations.libc import OneGadget, OneGadgetResult
from pwnariadne.integrations.tools import DebuggerFlavor
from pwnariadne.review.sinks import lookup


def _off(addr):
    return OverflowOffset(
        sink="gets", call_address=addr, in_function="main", dest_reg="rdi",
        buf_disp=0x40, offset_to_saved_rbp=0x40, offset_to_ret=0x48,
        offset_to_canary=0x38, confidence="high", asm=[],
    )


def test_offset_annotates_breakpoint():
    f = Finding(sink=lookup("gets"), address=0x4011C2, in_function="main")
    script = generate([f], offsets=[_off(0x4011C2)], flavor=DebuggerFlavor.GDB)
    assert "saved RIP = 72 (0x48)" in script
    assert "x/2gx $rbp" in script


def test_constraint_translation():
    assert "p/x $rsp & 0xf" in _constraint_to_gdb("rsp & 0xf == 0")
    assert "x/gx $rsp+0x40" in _constraint_to_gdb("[rsp+0x40] == NULL")
    assert "p/x $rcx" in _constraint_to_gdb("rcx == NULL")


def test_onegadget_helper_emitted():
    og = OneGadgetResult(
        libc="libc.so.6",
        gadgets=[OneGadget(offset=0x4F2A5, call="execve", constraints=["rcx == NULL"])],
    )
    script = generate([], onegadget=og)
    assert "define pa_onegadget" in script
    assert "0x4f2a5" in script


def test_observe_only_still_holds_with_offsets():
    f = Finding(sink=lookup("gets"), address=0x4011C2, in_function="main")
    script = generate([f], offsets=[_off(0x4011C2)], flavor=DebuggerFlavor.PWNDBG)
    for raw in script.splitlines():
        line = raw.strip()
        if line.startswith("#") or line.startswith("printf"):
            continue
        for cmd in ("return", "jump", "set {", "set variable"):
            assert not line.startswith(cmd)
