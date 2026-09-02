"""Two regular expressions over target-controlled text were quadratic in the whitespace on a line.

Measured before the fix, on a single line padded with 20,000 spaces:

    _PERSIST_CREDENTIALS_FALSE_RE.search   10.5 s   (an azure-pipelines.yml of the target)
    _ATX_HEADING_RE.match                   0.9 s   (a README heading of the target)

Both scale with the square of the padding, so a 200,000-space line -- 200 KB, well inside every
size limit the kit enforces -- would hold `evaluate` for minutes. The cause in each was two
adjacent whitespace quantifiers competing for the same run of spaces (`\\s*-?\\s*`, and a lazy
`(.*?)` against `\\s*$`). The rewritten patterns use one quantifier per run.

The bound here is loose on purpose. A linear match on 200,000 characters takes milliseconds; the
quadratic one takes over a minute. A one-second ceiling is two orders of magnitude from either,
so a slow CI runner cannot fail it and a regression cannot pass it.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from oss_policy_kit.application.evaluators._shared import _ATX_HEADING_RE, _markdown_sections
from oss_policy_kit.application.evaluators.azure import _PERSIST_CREDENTIALS_FALSE_RE

_PADDING = " " * 200_000
_CEILING_SECONDS = 1.0


def _seconds(fn: Callable[[], object]) -> float:
    started = time.perf_counter()
    fn()
    return time.perf_counter() - started


def test_a_padded_pipeline_line_is_matched_in_linear_time() -> None:
    # The padding sits where the quantifiers used to compete: before the key and before the
    # trailing text that makes the match FAIL, which is the path that backtracks.
    doc = f"steps:\n{_PADDING}persistCredentials : false{_PADDING}x\n"
    elapsed = _seconds(lambda: _PERSIST_CREDENTIALS_FALSE_RE.search(doc))
    assert elapsed < _CEILING_SECONDS, f"{elapsed:.2f}s on one padded line: the match is not linear"


def test_the_persist_credentials_match_still_reads_every_spelling_it_did() -> None:
    for text in (
        "persistCredentials: false",
        "  - persistCredentials : false   # no token in .git/config",
        "\tPERSISTCREDENTIALS:FALSE",
        "steps:\r\n  persistCredentials: false\r\n",
    ):
        assert _PERSIST_CREDENTIALS_FALSE_RE.search(text), text
    for text in ("persistCredentials: true", "persistCredentials: false-ish", "# persistCredentials: false"):
        assert not _PERSIST_CREDENTIALS_FALSE_RE.search(text), text


def test_a_padded_heading_line_is_matched_in_linear_time() -> None:
    line = f"#{_PADDING}title{_PADDING}!"
    elapsed = _seconds(lambda: _ATX_HEADING_RE.match(line))
    assert elapsed < _CEILING_SECONDS, f"{elapsed:.2f}s on one padded heading: the match is not linear"


def test_a_heading_title_is_still_trimmed_the_same_way() -> None:
    """The trailing-whitespace trim moved from the pattern to the consumer; the result is the same."""

    sections = _markdown_sections("##   Security Policy ##   \n\nbody\n\n### Reporting   \n\ntext\n")
    assert [heading for heading, _body in sections] == ["security policy", "reporting"]
