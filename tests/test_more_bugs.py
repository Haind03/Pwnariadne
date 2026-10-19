import pytest

from pwnariadne.review import treesitter_c
from pwnariadne.review.source import review_source

pytestmark = pytest.mark.skipif(
    not treesitter_c.available(), reason="tree-sitter not installed"
)

SAMPLE = """\
#include <stdlib.h>
#include <stdio.h>
char *bad(void) {
    char local[64];
    return local;
}
int *bad2(void) {
    int x = 5;
    return &x;
}
void alloc(int n) {
    char *p = malloc(n * 8);
    (void)p;
}
void inp(void) {
    char buf[16];
    int d;
    scanf("%d", &d);
    scanf("%s", buf);
    scanf("%15s", buf);
}
"""


def _by(tmp_path):
    src = tmp_path / "s.c"
    src.write_text(SAMPLE)
    out = {}
    for f in review_source([str(src)], backend="treesitter"):
        out.setdefault(f.sink.name, []).append(f.line)
    return out


def test_use_after_return_local_array_and_address(tmp_path):
    b = _by(tmp_path)
    assert "use-after-return" in b
    assert 5 in b["use-after-return"]  # return local;
    assert 9 in b["use-after-return"]  # return &x;


def test_alloc_size_overflow(tmp_path):
    b = _by(tmp_path)
    assert "alloc-size-overflow" in b
    assert 12 in b["alloc-size-overflow"]


def test_scanf_percent_d_not_flagged(tmp_path):
    b = _by(tmp_path)
    scanf_lines = b.get("scanf", [])
    assert 18 not in scanf_lines   # scanf("%d") is safe
    assert 20 not in scanf_lines   # scanf("%15s") is bounded
    assert 19 in scanf_lines       # scanf("%s") is flagged


def test_bug_classes_present(tmp_path):
    src = tmp_path / "s.c"
    src.write_text(SAMPLE)
    classes = {f.bug_class for f in review_source([str(src)], backend="treesitter")}
    assert "use-after-return" in classes
    assert "integer-overflow" in classes
