"""`strip_yaml_comments` replaces a comment with spaces and keeps the line ending as written.

The function is exercised by every text-scanning evaluator, but only through LF files: the
CRLF path had no test of its own, and when the newline detection was rewritten from one
conditional expression into an if/elif chain, the coverage gate showed the `\\r\\n` arm had
never executed. These cases pin the three endings a line can have and the two guarantees
the docstring makes: every column keeps its position, and the ending is the one found.
"""

from __future__ import annotations

import pytest

from oss_policy_kit.application.evaluators_common import strip_yaml_comments


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("persist-credentials: false # keep\r\n", "persist-credentials: false       \r\n"),
        ("persist-credentials: false # keep\n", "persist-credentials: false       \n"),
        ("persist-credentials: false # keep", "persist-credentials: false       "),
    ],
    ids=["crlf", "lf", "no-newline"],
)
def test_the_comment_is_blanked_and_the_ending_is_the_one_found(line: str, expected: str) -> None:
    out = strip_yaml_comments(line)
    assert out == expected
    assert len(out) == len(line), "a column moved: evaluators report positions into this text"


def test_a_crlf_file_keeps_every_carriage_return() -> None:
    text = "steps:\r\n  - run: echo hi # say hi\r\n  # whole-line comment\r\n  - uses: x\r\n"
    out = strip_yaml_comments(text)
    assert out.count("\r\n") == text.count("\r\n")
    assert "#" not in out
    assert len(out) == len(text)
