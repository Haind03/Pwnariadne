"""Assembly-level overflow offset solver, against the compiled demo."""

import shutil
import subprocess
from pathlib import Path

import pytest

from pwnariadne.core.elf import Binary
from pwnariadne.core.offsets import solve_overflow_offsets

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "vuln_demo"


def _ensure_demo() -> Path | None:
    if DEMO.exists():
        return DEMO
    if shutil.which("make") and shutil.which("gcc"):
        subprocess.run(["make", "vuln_demo"], cwd=DEMO.parent, check=True, capture_output=True)
        if DEMO.exists():
            return DEMO
    return None


def _by_sink(demo):
    with Binary(str(demo)) as b:
        return {o.sink: o for o in solve_overflow_offsets(b)}


def test_gets_offset_matches_buffer_size():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("vuln_demo not built")
    offs = _by_sink(demo)
    assert "gets" in offs
    g = offs["gets"]
    # echo_name: char buf[64] at rbp-0x40; saved RIP is 8 bytes above saved RBP.
    assert g.offset_to_saved_rbp == 0x40
    assert g.offset_to_ret == 0x40 + 8
    assert g.dest_reg == "rdi"


def test_strcpy_offset_uses_destination_buffer():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("vuln_demo not built")
    offs = _by_sink(demo)
    assert "strcpy" in offs
    s = offs["strcpy"]
    # copy_input: char dst[32] at rbp-0x20.
    assert s.offset_to_saved_rbp == 0x20
    assert s.offset_to_ret == 0x20 + 8


def test_asm_context_is_captured():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("vuln_demo not built")
    offs = _by_sink(demo)
    g = offs["gets"]
    assert any("lea" in line and "rbp" in line for line in g.asm)
    assert any("call" in line for line in g.asm)


def test_offset_to_canary_is_eight_below_saved_rbp():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("vuln_demo not built")
    offs = _by_sink(demo)
    g = offs["gets"]
    # canary lives at rbp-8, buffer at rbp-0x40: distance buf->canary = 0x40-8.
    assert g.offset_to_canary == g.offset_to_saved_rbp - 8
