from pwnariadne.classify.finding import Finding
from pwnariadne.gdbgen.generator import generate
from pwnariadne.integrations.tools import DebuggerFlavor
from pwnariadne.review.sinks import lookup


def test_fmt_helper_emitted_for_format_string():
    f = Finding(sink=lookup("printf"), address=0x4011B1, in_function="f")
    script = generate([f], flavor=DebuggerFlavor.GDB)
    assert "define pa_fmt" in script
    assert "%1$ (rsi)" in script
    assert "%6$" in script
    # format-string breakpoint should invoke it
    assert 'pa_safe("pa_fmt")' in script


def test_no_fmt_helper_without_format_string():
    f = Finding(sink=lookup("gets"), address=0x4011C2, in_function="f")
    script = generate([f], flavor=DebuggerFlavor.GDB)
    assert "define pa_fmt" not in script
