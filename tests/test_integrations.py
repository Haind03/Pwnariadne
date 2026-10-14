import shutil

import pytest

from pwnariadne.integrations import DebuggerFlavor, detect_debugger, detect_toolbox
from pwnariadne.integrations.gadgets import enumerate_gadgets
from pwnariadne.integrations.tools import Tool, Toolbox


def test_toolbox_reports_gdb_presence():
    box = detect_toolbox()
    gdb = box.get("gdb")
    assert gdb is not None
    assert gdb.available == bool(shutil.which("gdb"))


def test_toolbox_helpers():
    box = Toolbox(
        tools=[
            Tool("a", "cli", True),
            Tool("b", "cli", False),
        ]
    )
    assert box.has("a") is True
    assert box.has("b") is False
    assert {t.name for t in box.available()} == {"a"}
    assert {t.name for t in box.missing()} == {"b"}


def test_detect_debugger_prefers_explicit():
    assert detect_debugger(DebuggerFlavor.GEF) is DebuggerFlavor.GEF


def test_detect_debugger_returns_a_flavor():
    assert detect_debugger() in set(DebuggerFlavor)


def test_gadget_enumeration_fallback_when_absent(monkeypatch):
    # Force both finders to look absent: result is empty with a note, not a crash.
    monkeypatch.setattr("pwnariadne.integrations.gadgets.shutil.which", lambda _: None)
    res = enumerate_gadgets("examples/vuln_demo")
    assert res.tool is None
    assert res.gadgets == {}
    assert "no gadget finder" in res.note


def test_gadget_enumeration_on_demo():
    if not shutil.which("ROPgadget") and not shutil.which("ropper"):
        pytest.skip("no gadget finder installed")
    res = enumerate_gadgets("examples/vuln_demo")
    assert res.tool in ("ROPgadget", "ropper")
    assert res.total_scanned > 0
    # A "ret" or "leave ; ret" gadget is near-universal in a C binary.
    assert res.gadgets, "expected at least one curated gadget"
