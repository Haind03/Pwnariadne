from pwnariadne.review.sinks import all_names, lookup


def test_lookup_direct():
    assert lookup("gets").bug_class == "stack-buffer-overflow"
    assert lookup("printf").bug_class == "format-string"
    assert lookup("system").bug_class == "command-injection"


def test_lookup_strips_plt_decoration():
    assert lookup("gets@plt").name == "gets"
    assert lookup("printf@GLIBC_2.2.5").name == "printf"


def test_lookup_resolves_aliases():
    assert lookup("__isoc99_scanf").name == "scanf"
    assert lookup("__strcpy_chk").name == "strcpy"
    assert lookup("memmove").name == "memcpy"


def test_lookup_unknown_returns_none():
    assert lookup("definitely_not_a_sink") is None


def test_all_names_includes_aliases():
    names = all_names()
    assert "gets" in names
    assert "__isoc99_scanf" in names
