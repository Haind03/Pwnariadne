import pytest

from pwnariadne.review import treesitter_c
from pwnariadne.review.source import active_backend, review_source

pytestmark = pytest.mark.skipif(
    not treesitter_c.available(), reason="tree-sitter not installed"
)

SAMPLE = """\
#include <stdio.h>
#include <string.h>

void handler(char *name) {
    char buf[64];
    printf("prompt: ");      /* constant format, must be skipped */
    printf(name);            /* user-controlled format, must flag */
    gets(buf);               /* unbounded read, must flag */
    strcpy(buf,
           name);            /* call split across lines, must flag */
}
"""


def _write(tmp_path, text=SAMPLE):
    src = tmp_path / "s.c"
    src.write_text(text)
    return src


def test_backend_is_treesitter_when_available():
    assert active_backend("auto") == "treesitter"
    assert active_backend("treesitter") == "treesitter"
    assert active_backend("regex") == "regex"


def test_constant_format_string_is_not_flagged(tmp_path):
    src = _write(tmp_path)
    findings = review_source([str(src)], backend="treesitter")
    printf_lines = [f.line for f in findings if f.sink.name == "printf"]
    # Only the printf(name) call (line 7) is flagged, not printf("prompt: ").
    assert printf_lines == [7]


def test_enclosing_function_is_resolved(tmp_path):
    src = _write(tmp_path)
    findings = review_source([str(src)], backend="treesitter")
    assert findings
    assert all(f.in_function == "handler" for f in findings)


def test_multiline_call_is_found(tmp_path):
    src = _write(tmp_path)
    findings = review_source([str(src)], backend="treesitter")
    names = {f.sink.name for f in findings}
    assert {"gets", "strcpy", "printf"} <= names


def test_treesitter_and_regex_agree_on_dangerous_calls(tmp_path):
    src = _write(tmp_path)
    ts = {f.sink.name for f in review_source([str(src)], backend="treesitter")}
    rx = {f.sink.name for f in review_source([str(src)], backend="regex")}
    # Both must catch the genuinely dangerous calls.
    assert {"gets", "strcpy", "printf"} <= ts
    assert {"gets", "strcpy", "printf"} <= rx
