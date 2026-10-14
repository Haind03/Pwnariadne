"""Overflow offset solving for functions with no frame pointer (rsp frame)."""

import shutil
import subprocess
from pathlib import Path

import pytest

from pwnariadne.core.elf import Binary
from pwnariadne.core.offsets import solve_overflow_offsets

SRC = Path(__file__).resolve().parent.parent / "examples" / "vuln_demo.c"


def _build_nofp(tmp_path):
    if not (shutil.which("gcc") and SRC.exists()):
        return None
    out = tmp_path / "nofp"
    r = subprocess.run(
        ["gcc", "-fno-stack-protector", "-no-pie", "-fomit-frame-pointer",
         "-O1", "-w", "-o", str(out), str(SRC)],
        capture_output=True,
    )
    return out if out.exists() else None


def test_rsp_frame_offset_resolved(tmp_path):
    binpath = _build_nofp(tmp_path)
    if binpath is None:
        pytest.skip("gcc unavailable")
    with Binary(str(binpath)) as b:
        offs = {o.sink: o for o in solve_overflow_offsets(b)}
    assert "gets" in offs
    g = offs["gets"]
    assert g.frame_kind == "rsp"
    assert g.offset_to_saved_rbp == -1  # no frame pointer
    # push rbx (8) + sub rsp,0x40, buffer at rsp+0 -> 0x48 to the return address.
    assert g.offset_to_ret == 0x48
