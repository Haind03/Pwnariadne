import shutil

from pwnariadne.integrations.libc import (
    find_one_gadgets,
    parse_one_gadget,
    pwntools_checksec,
)

_SAMPLE = """\
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
  [rsp+0x78] == NULL
"""


def test_one_gadget_absent_is_graceful(monkeypatch):
    monkeypatch.setattr("pwnariadne.integrations.libc.shutil.which", lambda _: None)
    res = find_one_gadgets("/lib/x86_64-linux-gnu/libc.so.6")
    assert res.offsets == []
    assert "not installed" in res.note


def test_parse_one_gadget_extracts_offsets_and_constraints():
    gadgets = parse_one_gadget(_SAMPLE)
    assert [g.offset for g in gadgets] == [0x4F2A5, 0x4F302, 0x10A2FC]
    assert gadgets[0].call.startswith('execve("/bin/sh"')
    assert gadgets[0].constraints == ["rsp & 0xf == 0", "rcx == NULL"]
    assert gadgets[2].constraints == ["[rsp+0x70] == NULL", "[rsp+0x78] == NULL"]


def test_find_one_gadgets_parses_full_output(monkeypatch):
    monkeypatch.setattr(
        "pwnariadne.integrations.libc.shutil.which", lambda _: "/usr/bin/one_gadget"
    )

    class _Proc:
        stdout = _SAMPLE

    monkeypatch.setattr(
        "pwnariadne.integrations.libc.subprocess.run", lambda *a, **k: _Proc()
    )
    res = find_one_gadgets("libc.so.6")
    assert res.offsets == [0x4F2A5, 0x4F302, 0x10A2FC]
    assert len(res.gadgets) == 3
    assert res.gadgets[1].constraints == ["[rsp+0x40] == NULL"]
    assert res.note == ""


def test_pwntools_checksec_absent_is_graceful():
    # pwntools is an optional dependency; when absent the call must not raise.
    res = pwntools_checksec("examples/vuln_demo")
    if not res.available:
        assert "pwntools" in res.note
    else:
        # If pwntools happens to be installed, the data must be well formed.
        assert "relro" in res.data
