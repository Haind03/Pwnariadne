"""Indirect call detection against the compiled fptr_demo binary."""

import shutil
import subprocess
from pathlib import Path

import pytest

from pwnariadne.core.elf import Binary

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "fptr_demo"


def _ensure_demo() -> Path | None:
    if DEMO.exists():
        return DEMO
    if shutil.which("make") and shutil.which("gcc"):
        subprocess.run(["make", "fptr_demo"], cwd=DEMO.parent, check=True, capture_output=True)
        if DEMO.exists():
            return DEMO
    return None


def test_indirect_call_through_function_pointer_is_found():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("fptr_demo not built and no compiler available")

    with Binary(str(demo)) as binary:
        indirect = binary.indirect_call_sites()

    # The function-pointer call in main compiles to `call <reg>`.
    assert any(
        ic.in_function == "main" and ic.operand and not ic.operand.startswith("0x")
        for ic in indirect
    )
    # Every reported site is a call mnemonic with a non-immediate operand.
    for ic in indirect:
        assert ic.mnemonic == "call"
        assert not ic.operand.startswith("0x")


def test_architecture_note_is_full_for_x86():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("fptr_demo not built and no compiler available")

    with Binary(str(demo)) as binary:
        note = binary.architecture_note()
    assert "full" in note


def test_direct_calls_are_not_in_indirect_list():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("fptr_demo not built and no compiler available")

    with Binary(str(demo)) as binary:
        direct_addrs = {c.address for c in binary.call_sites()}
        indirect_addrs = {ic.address for ic in binary.indirect_call_sites()}
    assert direct_addrs.isdisjoint(indirect_addrs)
