import pytest

from pwnariadne.review import treesitter_c
from pwnariadne.review.source import review_source

pytestmark = pytest.mark.skipif(
    not treesitter_c.available(), reason="tree-sitter not installed"
)

SAMPLE = """\
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void trunc_(char *s){ short len = strlen(s); char n = read(0,s,100); (void)len;(void)n; }
void szptr(char *p, char *q){ memcpy(p, q, sizeof(p)); }
void ncp(char *src){ char dst[32]; strncpy(dst, src, sizeof(dst)); }
void al(int n){ for(int i=0;i<n;i++){ char *t = alloca(64); (void)t; } }
void ok(size_t m, char *s){ size_t z = strlen(s); (void)z;(void)m; }
"""


def _classes(tmp_path):
    src = tmp_path / "s.c"
    src.write_text(SAMPLE)
    out = {}
    for f in review_source([str(src)], backend="treesitter"):
        out.setdefault(f.sink.name, []).append(f.line)
    return out


def test_integer_truncation(tmp_path):
    c = _classes(tmp_path)
    assert "integer-truncation" in c
    assert 4 in c["integer-truncation"]
    assert 8 not in c["integer-truncation"]   # size_t z = strlen -> wide enough


def test_sizeof_pointer(tmp_path):
    c = _classes(tmp_path)
    assert "sizeof-pointer" in c
    assert 5 in c["sizeof-pointer"]


def test_strncpy_no_nul(tmp_path):
    c = _classes(tmp_path)
    assert "strncpy-no-nul" in c
    assert 6 in c["strncpy-no-nul"]


def test_alloca_in_loop(tmp_path):
    c = _classes(tmp_path)
    assert "alloca-in-loop" in c
    assert 7 in c["alloca-in-loop"]
