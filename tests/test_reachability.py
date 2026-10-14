from pwnariadne.integrations import angr_reach
from pwnariadne.integrations.angr_reach import ReachResult, reachable_sinks


def test_empty_targets_is_fine():
    res = reachable_sinks("examples/vuln_demo", [])
    assert res.available is True
    assert res.reachable == {}
    assert "no binary sink addresses" in res.note


def test_without_angr_degrades_gracefully():
    if angr_reach.available():
        import pytest

        pytest.skip("angr is installed; the absent path is not exercised here")
    res = reachable_sinks("examples/vuln_demo", [0x401000])
    assert res.available is False
    assert "angr not installed" in res.note
    assert res.reachable == {}


def test_result_shape():
    res = ReachResult(available=True, reachable={0x1000: True, 0x2000: False})
    assert res.reachable[0x1000] is True
    assert res.reachable[0x2000] is False


def test_with_angr_marks_reachable(tmp_path):
    if not angr_reach.available():
        import pytest

        pytest.skip("angr not installed")
    # When angr is present, a real binary analysis must return verdicts.
    from pwnariadne.core.elf import Binary

    with Binary("examples/vuln_demo") as b:
        targets = [c.address for c in b.call_sites()]
    res = reachable_sinks("examples/vuln_demo", targets)
    assert res.available is True
    assert set(res.reachable) == set(targets)
