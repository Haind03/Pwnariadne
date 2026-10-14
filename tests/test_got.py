import shutil
import subprocess
from pathlib import Path

import pytest

from pwnariadne.core.elf import Binary
from pwnariadne.report import reporter

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "vuln_demo"


def _demo():
    if DEMO.exists():
        return DEMO
    if shutil.which("make") and shutil.which("gcc"):
        subprocess.run(["make", "vuln_demo"], cwd=DEMO.parent, check=True, capture_output=True)
        return DEMO if DEMO.exists() else None
    return None


def test_got_entries_resolve_known_imports():
    demo = _demo()
    if demo is None:
        pytest.skip("vuln_demo not built")
    with Binary(str(demo)) as b:
        got = b.got_entries()
    assert "gets" in got and "printf" in got
    assert all(isinstance(a, int) and a > 0 for a in got.values())


def test_markdown_got_section_notes_writable():
    demo = _demo()
    if demo is None:
        pytest.skip("vuln_demo not built")
    with Binary(str(demo)) as b:
        got = b.got_entries()
        mit = b.mitigations()
    md = reporter.to_markdown([], mit, got=got)
    assert "## GOT entries" in md
    # vuln_demo is Partial RELRO -> writable.
    assert "writable" in md


def test_markdown_pie_note():
    from pwnariadne.core.elf import Mitigations

    pie = Mitigations(arch="x64", bits=64, relro="full", canary=True, nx=True, pie=True)
    md = reporter.to_markdown([], pie)
    assert "PIE is enabled" in md
