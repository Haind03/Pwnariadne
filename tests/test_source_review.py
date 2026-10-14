from pathlib import Path

from pwnariadne.review.source import review_source

SAMPLE = """\
#include <stdio.h>
void f(char *s) {
    char buf[16];
    strcpy(buf, s);     // unsafe
    gets(buf);
    printf(s);
    // strcpy(buf, s);  commented out, should be skipped
}
"""


def test_review_source_flags_sinks(tmp_path: Path):
    src = tmp_path / "f.c"
    src.write_text(SAMPLE)

    findings = review_source([str(src)])
    names = sorted(f.sink.name for f in findings)

    assert "strcpy" in names
    assert "gets" in names
    assert "printf" in names
    # The commented-out strcpy line must not add a second strcpy hit.
    assert names.count("strcpy") == 1


def test_review_source_records_line_numbers(tmp_path: Path):
    src = tmp_path / "f.c"
    src.write_text(SAMPLE)

    findings = review_source([str(src)])
    gets_finding = next(f for f in findings if f.sink.name == "gets")
    assert gets_finding.line == 5
    assert gets_finding.source_file == str(src)
