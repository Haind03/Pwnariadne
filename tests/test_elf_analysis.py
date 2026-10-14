"""End-to-end check against the compiled demo binary.

Skips cleanly if the demo has not been built yet (no compiler in CI, etc.).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from pwnariadne.classify import finding as finding_mod
from pwnariadne.core.elf import Binary
from pwnariadne.gdbgen import generator

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "vuln_demo"


def _ensure_demo() -> Path | None:
    if DEMO.exists():
        return DEMO
    if shutil.which("make") and shutil.which("gcc"):
        subprocess.run(["make"], cwd=DEMO.parent, check=True, capture_output=True)
        if DEMO.exists():
            return DEMO
    return None


def test_finds_known_sinks_in_demo():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("demo binary not built and no compiler available")

    with Binary(str(demo)) as binary:
        findings = finding_mod.from_call_sites(binary.call_sites())

    names = {f.sink.name for f in findings}
    assert "gets" in names
    assert "strcpy" in names
    assert "printf" in names

    # Findings must be sorted by descending severity.
    sevs = [f.severity for f in findings]
    assert sevs == sorted(sevs, reverse=True)


def test_mitigations_detected_on_demo():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("demo binary not built and no compiler available")

    with Binary(str(demo)) as binary:
        m = binary.mitigations()

    # Built with -fno-stack-protector -no-pie.
    assert m.canary is False
    assert m.pie is False
    assert m.bits == 64


def test_gdb_script_contains_breakpoints():
    demo = _ensure_demo()
    if demo is None:
        pytest.skip("demo binary not built and no compiler available")

    with Binary(str(demo)) as binary:
        findings = finding_mod.from_call_sites(binary.call_sites())

    script = generator.generate(findings, target=str(demo))
    assert "break *0x" in script

    # Observe-only guarantee: no state-changing GDB *command* slips in.
    # Check command lines only (printf/comment text may mention these words).
    forbidden = ("set {", "set variable", "return", "jump", "call ", "write")
    for raw in script.splitlines():
        line = raw.strip()
        if line.startswith("#") or line.startswith("printf"):
            continue
        for cmd in forbidden:
            assert not line.startswith(cmd), f"unexpected command: {line!r}"
