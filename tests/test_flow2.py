import pytest

from pwnariadne.review import treesitter_c
from pwnariadne.review.source import review_source

pytestmark = pytest.mark.skipif(
    not treesitter_c.available(), reason="tree-sitter not installed"
)

SAMPLE = """\
#include <stdlib.h>
#include <string.h>
#include <time.h>
void df(void){ char *p = malloc(8); free(p); free(p); }
void df_ok(void){ char *q = malloc(8); free(q); q = malloc(8); free(q); }
int token(void){ srand(time(0)); return rand(); }
void cpy(char *d, char *s, int n){ memcpy(d, s, n); }
void cpy_ok(char *d, char *s, size_t n){ memcpy(d, s, n); }
"""


def _classes(tmp_path):
    src = tmp_path / "s.c"
    src.write_text(SAMPLE)
    out = {}
    for f in review_source([str(src)], backend="treesitter"):
        out.setdefault(f.sink.name, []).append(f.line)
    return out


def test_double_free_detected_once(tmp_path):
    c = _classes(tmp_path)
    assert "double-free" in c
    assert 4 in c["double-free"]          # df()
    # df_ok reassigns between frees -> not flagged
    assert all(ln != 5 for ln in c["double-free"])


def test_weak_prng(tmp_path):
    c = _classes(tmp_path)
    assert "weak-prng" in c
    assert 6 in c["weak-prng"]


def test_signed_size_only_for_signed(tmp_path):
    c = _classes(tmp_path)
    assert "signed-size" in c
    assert 7 in c["signed-size"]          # int n
    assert 8 not in c["signed-size"]      # size_t n


def test_free_not_null_deref(tmp_path):
    # free(NULL) is safe, so free must not be flagged as unchecked-malloc.
    c = _classes(tmp_path)
    assert "unchecked-malloc" not in c
