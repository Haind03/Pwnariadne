import shutil

from pwnariadne.integrations.libc import (
    find_one_gadgets,
    pwntools_checksec,
)


def test_one_gadget_absent_is_graceful(monkeypatch):
    monkeypatch.setattr("pwnariadne.integrations.libc.shutil.which", lambda _: None)
    res = find_one_gadgets("/lib/x86_64-linux-gnu/libc.so.6")
    assert res.offsets == []
    assert "not installed" in res.note


def test_one_gadget_parses_raw_output(monkeypatch):
    monkeypatch.setattr(
        "pwnariadne.integrations.libc.shutil.which", lambda _: "/usr/bin/one_gadget"
    )

    class _Proc:
        stdout = "0x4f2a5 0x4f302 0x10a2fc"

    monkeypatch.setattr(
        "pwnariadne.integrations.libc.subprocess.run", lambda *a, **k: _Proc()
    )
    res = find_one_gadgets("libc.so.6")
    assert res.offsets == [0x4F2A5, 0x4F302, 0x10A2FC]
    assert res.note == ""


def test_pwntools_checksec_absent_is_graceful():
    # pwntools is an optional dependency; when absent the call must not raise.
    res = pwntools_checksec("examples/vuln_demo")
    if not res.available:
        assert "pwntools" in res.note
    else:
        # If pwntools happens to be installed, the data must be well formed.
        assert "relro" in res.data
