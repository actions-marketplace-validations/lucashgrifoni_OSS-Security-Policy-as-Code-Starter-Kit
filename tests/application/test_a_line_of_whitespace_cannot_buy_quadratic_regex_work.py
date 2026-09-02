"""Two regular expressions over target-controlled text were quadratic in the whitespace on a line.

The pipeline pattern reads an ``azure-pipelines.yml`` of the target; the heading pattern reads its
README. Both had two whitespace quantifiers competing for the same run of spaces (``\\s*-?\\s*``,
and a lazy ``(.*?)`` against ``\\s*$``), so the cost grew with the square of the padding. A line
padded to 200 KB is inside every size limit the kit enforces and would have held ``evaluate`` for
minutes.

Padding of 20,000 is deliberate, and it is the whole design of this guard. Measured on the
maintainer's machine:

    padding      persist (quadratic)   atx (quadratic)   both, linear
    10,000              1.59 s              0.22 s          < 1 ms
    20,000             12.67 s              2.09 s          < 1 ms

The ceiling is 0.5 s. The linear forms sit four orders of magnitude under it, so no runner is slow
enough to fail this by accident; the quadratic forms are 4x and 25x over it, so neither can pass.
A larger padding would prove linearity more loudly and detect a regression worse: at 200,000 the
quadratic form does not fail the assertion, it runs for minutes and the CI job dies on its own
timeout, which reads as an infrastructure problem rather than as this test finding the defect.
Verified by mutation: with either pattern reverted, the matching case fails in seconds.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from oss_policy_kit.application.evaluators._shared import _ATX_HEADING_RE, _markdown_sections
from oss_policy_kit.application.evaluators.azure import _PERSIST_CREDENTIALS_FALSE_RE

_PADDING = " " * 20_000
_CEILING_SECONDS = 0.5


def _seconds(fn: Callable[[], object]) -> float:
    started = time.perf_counter()
    fn()
    return time.perf_counter() - started


def test_a_padded_pipeline_line_is_matched_in_linear_time() -> None:
    # The padding sits where the quantifiers used to compete: before the key, and before the
    # trailing text that makes the match FAIL, which is the path that backtracks.
    doc = f"steps:\n{_PADDING}persistCredentials : false{_PADDING}x\n"
    elapsed = _seconds(lambda: _PERSIST_CREDENTIALS_FALSE_RE.search(doc))
    assert elapsed < _CEILING_SECONDS, (
        f"{elapsed:.2f}s on one padded line, against a {_CEILING_SECONDS}s ceiling that the linear "
        "form clears by four orders of magnitude. The pattern backtracks, and the line comes from "
        "the target's own pipeline."
    )


def test_a_padded_heading_line_is_matched_in_linear_time() -> None:
    line = f"#{_PADDING}title{_PADDING}!"
    elapsed = _seconds(lambda: _ATX_HEADING_RE.match(line))
    assert elapsed < _CEILING_SECONDS, (
        f"{elapsed:.2f}s on one padded heading, against a {_CEILING_SECONDS}s ceiling. The pattern "
        "backtracks, and the line comes from the target's own README."
    )


def test_the_persist_credentials_match_still_reads_every_spelling_it_did() -> None:
    """Speed is worthless if the pattern stopped recognising the setting."""

    for text in (
        "persistCredentials: false",
        "  - persistCredentials : false   # no token in .git/config",
        "\tPERSISTCREDENTIALS:FALSE",
        "steps:\r\n  persistCredentials: false\r\n",
    ):
        assert _PERSIST_CREDENTIALS_FALSE_RE.search(text), text
    for text in ("persistCredentials: true", "persistCredentials: false-ish", "# persistCredentials: false"):
        assert not _PERSIST_CREDENTIALS_FALSE_RE.search(text), text


def test_a_heading_title_is_still_trimmed_the_same_way() -> None:
    """The trailing-whitespace trim moved from the pattern to the consumer; the result is the same."""

    sections = _markdown_sections("##   Security Policy ##   \n\nbody\n\n### Reporting   \n\ntext\n")
    assert [heading for heading, _body in sections] == ["security policy", "reporting"]


def test_a_heading_with_no_title_is_still_an_empty_heading() -> None:
    """The title group became optional so it could open with a non-space; empty must still parse."""

    sections = _markdown_sections("#    \n\nbody\n")
    assert sections == [("", "\nbody")]
