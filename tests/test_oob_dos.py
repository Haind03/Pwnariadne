import pytest

from pwnariadne.review import treesitter_c
from pwnariadne.review.source import review_source

pytestmark = pytest.mark.skipif(
    not treesitter_c.available(), reason="tree-sitter not installed"
)

SAMPLE = """\
int table[100];
int pick(int i) {
    char vla[i];
    int x = 1000 / i;
    char safe[32];
    int y = 1000 / 4;
    return table[i] + x + safe[0] + table[3];
}
"""


def _findings(tmp_path):
    src = tmp_path / "o.c"
    src.write_text(SAMPLE)
    out = {}
    for f in review_source([str(src)], backend="treesitter"):
        out.setdefault(f.sink.name, []).append(f)
    return out


def test_oob_on_tainted_index(tmp_path):
    f = _findings(tmp_path)
    assert "array-index" in f
    # table[i] (tainted) is flagged; table[3] (constant) is not.
    lines = [x.line for x in f["array-index"]]
    assert 7 in lines  # table[i]
    assert all(x.bug_class == "out-of-bounds" for x in f["array-index"])


def test_divzero_on_tainted_divisor(tmp_path):
    f = _findings(tmp_path)
    assert "division" in f
    # 1000 / i (tainted) flagged; 1000 / 4 (constant) not.
    assert any(x.line == 4 for x in f["division"])
    assert all(x.line != 6 for x in f["division"])


def test_vla_flagged(tmp_path):
    f = _findings(tmp_path)
    assert "variable-length-array" in f
    assert f["variable-length-array"][0].bug_class == "denial-of-service"


def test_constant_array_not_flagged(tmp_path):
    f = _findings(tmp_path)
    # safe[32] is a fixed-size declaration, not a VLA.
    vlas = f.get("variable-length-array", [])
    assert all("safe" not in v.snippet for v in vlas)
