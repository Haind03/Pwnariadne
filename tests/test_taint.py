import pytest

from pwnariadne.review import treesitter_c
from pwnariadne.review.source import review_source

pytestmark = pytest.mark.skipif(
    not treesitter_c.available(), reason="tree-sitter not installed"
)

SAMPLE = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void f(char *name) {
    char buf[64];
    char local[64] = "hello";
    char *e = getenv("X");
    strcpy(buf, name);        /* tainted: name is a parameter */
    strcpy(buf, local);       /* local: no external influence */
    system(e);                /* tainted: e from getenv */
    system("/bin/ls");        /* constant */
    gets(buf);                /* tainted: inherently external */
    printf(name);             /* tainted: user-controlled format */
}
"""


def _taints(tmp_path):
    src = tmp_path / "t.c"
    src.write_text(SAMPLE)
    out = {}
    for f in review_source([str(src)], backend="treesitter"):
        out[(f.sink.name, f.line)] = f.taint
    return out


def test_param_source_is_tainted(tmp_path):
    t = _taints(tmp_path)
    assert t[("strcpy", 9)] == "tainted"


def test_local_source_is_local(tmp_path):
    t = _taints(tmp_path)
    assert t[("strcpy", 10)] == "local"


def test_getenv_propagates_to_system(tmp_path):
    t = _taints(tmp_path)
    assert t[("system", 11)] == "tainted"


def test_constant_argument_is_constant(tmp_path):
    t = _taints(tmp_path)
    assert t[("system", 12)] == "constant"


def test_inherently_external_sink_is_tainted(tmp_path):
    t = _taints(tmp_path)
    assert t[("gets", 13)] == "tainted"


def test_user_controlled_format_is_tainted(tmp_path):
    t = _taints(tmp_path)
    assert t[("printf", 14)] == "tainted"
