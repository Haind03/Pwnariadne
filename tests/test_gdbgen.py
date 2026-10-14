from pwnariadne.classify.finding import Finding
from pwnariadne.gdbgen import generator
from pwnariadne.integrations.tools import DebuggerFlavor
from pwnariadne.review.sinks import lookup


def _findings():
    return [
        Finding(sink=lookup("gets"), address=0x4011C2, in_function="echo_name"),
        Finding(sink=lookup("printf"), address=0x4011B1, in_function="echo_name"),
        Finding(sink=lookup("free"), address=0x401200, in_function="freer"),
    ]


def test_pwndbg_flavor_uses_pwndbg_commands():
    script = generator.generate(_findings(), flavor=DebuggerFlavor.PWNDBG)
    assert 'pa_safe("context")' in script
    assert 'pa_safe("canary")' in script  # stack overflow extra
    assert 'pa_safe("got")' in script  # format-string extra
    assert 'pa_safe("vis_heap_chunks")' in script  # heap extra


def test_gdb_flavor_uses_plain_commands_only():
    script = generator.generate(_findings(), flavor=DebuggerFlavor.GDB)
    assert 'pa_safe("info registers")' in script
    assert "context" not in script
    assert "telescope" not in script


def test_gef_flavor_uses_heap_chunks():
    script = generator.generate(_findings(), flavor=DebuggerFlavor.GEF)
    assert 'pa_safe("heap chunks")' in script


def test_script_is_observe_only_any_flavor():
    for flavor in DebuggerFlavor:
        script = generator.generate(_findings(), flavor=flavor)
        for raw in script.splitlines():
            line = raw.strip()
            if line.startswith("#") or line.startswith("printf"):
                continue
            for cmd in ("return", "jump", "set {", "set variable"):
                assert not line.startswith(cmd), f"{flavor}: unexpected {line!r}"


def test_safe_helper_present():
    script = generator.generate(_findings(), flavor=DebuggerFlavor.PWNDBG)
    assert "def pa_safe(cmd):" in script
    assert "gdb.error" in script
