from pwnariadne.classify.finding import Finding
from pwnariadne.review.sinks import lookup
from pwnariadne.techniques.heap import analyze_heap
from pwnariadne.techniques.hint import Signals


def _f(name):
    return Finding(sink=lookup(name), address=0x1000, in_function="main")


def _names(hints):
    return {h.name for h in hints}


def test_no_heap_findings_yields_nothing():
    assert analyze_heap([_f("gets")], Signals()) == []


def test_uaf_flagged_from_free():
    hints = analyze_heap([_f("free")], Signals())
    assert "heap: use-after-free (UAF)" in _names(hints)


def test_double_free_flagged_with_two_frees():
    hints = analyze_heap([_f("free"), _f("free")], Signals())
    assert any("double-free" in n for n in _names(hints))


def test_single_free_no_double_free():
    hints = analyze_heap([_f("free")], Signals())
    assert not any("double-free" in n for n in _names(hints))


def test_tcache_poisoning_needs_free_and_malloc():
    hints = analyze_heap([_f("free"), _f("malloc")], Signals())
    assert any("tcache poisoning" in n for n in _names(hints))


def test_unsorted_bin_leak_needs_free_and_malloc():
    hints = analyze_heap([_f("free"), _f("malloc")], Signals())
    assert any("unsorted-bin" in n for n in _names(hints))


def test_every_heap_hint_has_a_reference():
    hints = analyze_heap([_f("free"), _f("free"), _f("malloc")], Signals())
    assert hints
    assert all(h.references for h in hints)


def test_house_of_force_on_heap_overflow():
    # malloc is classified heap-overflow, which enables the top-chunk attacks.
    hints = analyze_heap([_f("malloc")], Signals())
    assert any("House of Force" in n for n in _names(hints))


def test_fsop_requires_stdio_imports():
    findings = [_f("free"), _f("free"), _f("malloc")]
    without = _names(analyze_heap(findings, Signals()))
    with_stdio = _names(analyze_heap(findings, Signals(imports={"puts", "printf"})))
    assert not any("FSOP" in n for n in without)
    assert any("FSOP" in n for n in with_stdio)


def test_large_bin_attack_listed():
    hints = analyze_heap([_f("free"), _f("malloc")], Signals())
    assert any("large bin attack" in n for n in _names(hints))
