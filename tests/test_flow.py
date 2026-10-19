import pytest

from pwnariadne.review import treesitter_c
from pwnariadne.review.source import review_source

pytestmark = pytest.mark.skipif(
    not treesitter_c.available(), reason="tree-sitter not installed"
)

SAMPLE = """\
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
int uninit(void){ int x; return x + 1; }
int okinit(void){ int y; y = 5; return y; }
void nd(void){ char *p = malloc(64); p[0] = 'A'; }
void nd_ok(void){ char *q = malloc(64); if(!q) return; q[0]='A'; }
void toc(const char *path){
    if (access(path, 0) == 0) { int fd = open(path, 0); (void)fd; }
}
void obo(int *a, int n){ for (int i = 0; i <= n; i++) a[i] = 0; }
void obo_ok(int *a, int n){ for (int i = 0; i < n; i++) a[i] = 0; }
"""


def _classes(tmp_path):
    src = tmp_path / "s.c"
    src.write_text(SAMPLE)
    out = {}
    for f in review_source([str(src)], backend="treesitter"):
        out.setdefault(f.sink.name, []).append(f.line)
    return out


def test_uninitialised_use(tmp_path):
    c = _classes(tmp_path)
    assert "uninitialised-use" in c
    assert 4 in c["uninitialised-use"]        # uninit()
    # okinit() assigns before reading -> not flagged
    assert all(5 != ln for ln in c["uninitialised-use"])


def test_null_deref_before_check(tmp_path):
    c = _classes(tmp_path)
    assert "unchecked-malloc" in c
    assert 6 in c["unchecked-malloc"]         # nd()
    assert 7 not in c["unchecked-malloc"]     # nd_ok() checked first


def test_toctou(tmp_path):
    c = _classes(tmp_path)
    assert "toctou" in c
    assert 9 in c["toctou"]


def test_off_by_one_only_for_le(tmp_path):
    c = _classes(tmp_path)
    assert "off-by-one-loop" in c
    # obo uses <= (line 11); obo_ok uses < (line 12) and must not be flagged
    assert 11 in c["off-by-one-loop"]
    assert 12 not in c["off-by-one-loop"]
