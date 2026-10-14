from pwnariadne.classify.finding import Finding
from pwnariadne.report import reporter
from pwnariadne.review.sinks import lookup


def _bin_finding():
    return Finding(sink=lookup("gets"), address=0x4011C2, in_function="echo_name")


def _src_finding():
    return Finding(
        sink=lookup("strcpy"),
        address=None,
        in_function="?",
        source_file="src/f.c",
        line=42,
    )


def test_endpoints_binary_uses_hex_address():
    out = reporter.to_endpoints([_bin_finding()])
    assert out == "0x4011c2\tgets\tstack-buffer-overflow"


def test_endpoints_source_uses_file_line():
    out = reporter.to_endpoints([_src_finding()])
    assert out == "src/f.c:42\tstrcpy\tstack-buffer-overflow"


def test_endpoints_one_line_per_finding():
    out = reporter.to_endpoints([_bin_finding(), _src_finding()])
    assert len(out.splitlines()) == 2


def test_endpoints_empty():
    assert reporter.to_endpoints([]) == ""
