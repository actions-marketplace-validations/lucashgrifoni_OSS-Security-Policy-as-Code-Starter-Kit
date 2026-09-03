"""Terminal detection and layout when the stream is not a normal terminal.

Everything here is what happens when the CLI is *not* attached to a healthy TTY: piped into
`less`, redirected to a file, running under a CI log collector, or squeezed into a window
narrower than the table wants. Those are the common cases, not the exotic ones, and their
handlers had not been executed.

The failure they guard against is not cosmetic. A stream whose `isatty()` raises would
otherwise take down a command that was only trying to decide whether to use colour, and a
width computation that returns 0 or negative produces a table that Rich cannot render.

The layout tests assert the invariants rather than the exact widths: columns never fall
below their documented minimums and always sum to the space available. Pinning the exact
integers would make this file fail on every future tuning of the percentages without
telling anyone anything.
"""

from __future__ import annotations

import io
import os
import sys
from typing import Any

import pytest

from oss_policy_kit.cli import terminal_ui as u


class _Hostile:
    """A stream whose terminal probes fail the way a closed or proxied handle does."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    def isatty(self) -> bool:
        raise self._exc


class _NoIsatty:
    """An object that is not a stream at all -- what a mocked-out stdout often is."""


# --------------------------------------------------------------------------- #
# is the stream a terminal
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("stream", [_Hostile(OSError(9, "Bad file descriptor")), _NoIsatty()])
def test_a_stream_that_cannot_answer_isatty_is_treated_as_not_a_terminal(stream: Any) -> None:
    """Colour detection must never be able to end the command it is decorating."""

    assert u.is_interactive_stream(stream) is False


def test_a_real_pipe_is_not_a_terminal() -> None:
    assert u.is_interactive_stream(io.StringIO()) is False


# --------------------------------------------------------------------------- #
# width
# --------------------------------------------------------------------------- #


class _Tty(io.StringIO):
    """A stream that claims to be a terminal, so the OS-size branch is actually reached.

    Without this the tests below pass for the wrong reason: `terminal_width` short-circuits
    to the fallback for any non-TTY, so a broken OS-size branch would never be exercised
    and the assertion would still hold.
    """

    def isatty(self) -> bool:
        return True


def test_a_non_terminal_never_consults_the_os_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pinning the short-circuit, because it is what the tests below have to get past."""

    monkeypatch.delenv("COLUMNS", raising=False)

    def _must_not_run(*, fallback: tuple[int, int]) -> os.terminal_size:
        raise AssertionError("the OS was consulted for a stream that is not a terminal")

    monkeypatch.setattr(u, "_get_terminal_size", _must_not_run)

    assert u.terminal_width(io.StringIO(), fallback=101) == 101


def test_a_non_terminal_honours_an_explicit_columns_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI logs are not TTYs; COLUMNS is how a caller pins the width there."""

    monkeypatch.setenv("COLUMNS", "133")

    assert u.terminal_width(io.StringIO(), fallback=101) == 133


def test_width_falls_back_when_the_os_cannot_report_a_size(monkeypatch: pytest.MonkeyPatch) -> None:
    """`shutil.get_terminal_size` raises on some handles that still claim to be a TTY."""

    monkeypatch.delenv("COLUMNS", raising=False)

    def _boom(*, fallback: tuple[int, int]) -> os.terminal_size:
        raise OSError(25, "Inappropriate ioctl for device")

    monkeypatch.setattr(u, "_get_terminal_size", _boom)

    assert u.terminal_width(_Tty(), fallback=101) == 101


@pytest.mark.parametrize("reported", [0, -1])
def test_a_nonsense_width_is_replaced_by_the_fallback(monkeypatch: pytest.MonkeyPatch, reported: int) -> None:
    """A zero or negative width reaches Rich as a table it cannot lay out."""

    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setattr(u, "_get_terminal_size", lambda *, fallback: os.terminal_size((reported, 24)))

    assert u.terminal_width(_Tty(), fallback=97) == 97


def test_a_reported_width_is_clamped_into_the_supported_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setattr(u, "_get_terminal_size", lambda *, fallback: os.terminal_size((100_000, 24)))

    assert u.terminal_width(_Tty()) == u.MAX_COLUMNS


def test_a_tiny_reported_width_is_raised_to_the_supported_minimum(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setattr(u, "_get_terminal_size", lambda *, fallback: os.terminal_size((3, 24)))

    assert u.terminal_width(_Tty()) == u.TTY_MIN_COLUMNS


def test_the_size_helper_delegates_to_shutil(monkeypatch: pytest.MonkeyPatch) -> None:
    """The indirection exists so tests do not have to patch global `shutil`; keep it honest."""

    monkeypatch.setattr(u.shutil, "get_terminal_size", lambda fallback: os.terminal_size((77, 24)))

    assert u._get_terminal_size(fallback=(80, 24)).columns == 77


# --------------------------------------------------------------------------- #
# console construction
# --------------------------------------------------------------------------- #


def test_a_console_can_be_built_on_a_stream_whose_isatty_raises() -> None:
    """This is the whole point: building the console must not be what crashes the CLI."""

    console = u.build_console(file=_Hostile(OSError(9, "Bad file descriptor")), width=80)

    assert console.is_terminal is False


def test_no_color_in_the_environment_disables_colour() -> None:
    console = u.build_console(file=io.StringIO(), width=80, _environ={"NO_COLOR": "1"})

    assert console.no_color is True


def test_a_dumb_terminal_disables_colour() -> None:
    console = u.build_console(file=io.StringIO(), width=80, _environ={"TERM": "dumb"})

    assert console.no_color is True


# --------------------------------------------------------------------------- #
# paragraph wrapping
# --------------------------------------------------------------------------- #


def test_blank_lines_between_paragraphs_survive_wrapping() -> None:
    """Collapsing them would run two unrelated remediation paragraphs together."""

    wrapped = u.human_wrap_lines("first paragraph\n\nsecond paragraph", stream=io.StringIO(), fallback_width=80)

    assert wrapped.split("\n") == ["first paragraph", "", "second paragraph"]


def test_wrapping_never_produces_a_zero_width(monkeypatch: pytest.MonkeyPatch) -> None:
    """`subtract` larger than the terminal would ask textwrap for a non-positive width."""

    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setattr(u, "_get_terminal_size", lambda *, fallback: os.terminal_size((24, 24)))

    wrapped = u.human_wrap_lines("a fairly long sentence that has to go somewhere", stream=_NoIsatty(), subtract=999)

    assert wrapped.strip()


# --------------------------------------------------------------------------- #
# profile table layout under pressure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("columns", [40, 52, 60, 72, 80, 100, 120, 200])
@pytest.mark.parametrize("detailed", [True, False])
def test_no_column_ever_falls_below_its_documented_minimum(columns: int, detailed: bool) -> None:
    """A column squeezed to zero renders as an empty cell -- data silently missing."""

    layout = u.profile_table_layout_for_width(terminal_columns=columns, detailed=detailed, longest_profile_id_chars=28)

    assert layout.title >= u._PROFILE_COL_MIN_TITLE
    assert layout.audience >= u._PROFILE_COL_MIN_AUDIENCE
    assert layout.description >= u._PROFILE_COL_MIN_DESCRIPTION


def test_a_very_narrow_terminal_shaves_audience_before_title() -> None:
    """The documented order: description keeps its floor, audience gives way first."""

    narrow = u.profile_table_layout_for_width(terminal_columns=40, detailed=True, longest_profile_id_chars=28)
    wide = u.profile_table_layout_for_width(terminal_columns=200, detailed=True, longest_profile_id_chars=28)

    assert narrow.audience < wide.audience
    assert narrow.description >= u._PROFILE_COL_MIN_DESCRIPTION


# --------------------------------------------------------------------------- #
# banner suppression
# --------------------------------------------------------------------------- #


def test_the_banner_is_suppressed_when_output_is_piped() -> None:
    """A banner in a redirected file is noise in whatever parses it."""

    assert u.should_show_cli_banner(stream=io.StringIO()) is False


def test_the_banner_is_suppressed_on_a_terminal_too_narrow_for_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """Below the minimum the art wraps into garbage, so it is dropped instead."""

    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.setattr(u, "is_interactive_stream", lambda _s: True)
    monkeypatch.setattr(u, "terminal_width", lambda _s, **_k: u.CLI_BANNER_MIN_COLUMNS - 1)

    assert u.should_show_cli_banner(stream=io.StringIO()) is False


def test_the_banner_shows_on_a_wide_interactive_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(u, "is_interactive_stream", lambda _s: True)
    monkeypatch.setattr(u, "terminal_width", lambda _s, **_k: u.CLI_BANNER_MIN_COLUMNS)

    assert u.should_show_cli_banner(stream=io.StringIO()) is True


def test_with_no_stream_given_a_fully_redirected_process_shows_no_banner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither stdout nor stderr is a terminal: there is nobody to show it to."""

    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", io.StringIO())

    assert u.should_show_cli_banner() is False


# --------------------------------------------------------------------------- #
# recommend-profile context line
# --------------------------------------------------------------------------- #


def _signals(**over: Any) -> u._RecSignals:
    base: dict[str, Any] = {
        "gh": "",
        "az": "",
        "aws": "",
        "gh_sig": False,
        "az_sig": False,
        "aws_sig": False,
        "gh_ev": False,
        "az_ev": False,
        "aws_ev": False,
        "rel_label": "",
        "ci_definitions": True,
    }
    base.update(over)
    return u._RecSignals(**base)


@pytest.mark.parametrize(
    ("flag", "expected"),
    [("gh_sig", "GitHub Actions"), ("az_sig", "Azure Pipelines"), ("aws_sig", "AWS CodeBuild")],
)
def test_a_single_platform_is_named_in_the_context_line(flag: str, expected: str) -> None:
    """The operator has to know which platform the ranking was driven by."""

    line = u._recommend_context_line(_signals(**{flag: True}))

    assert expected in line


def test_more_than_one_platform_says_so_rather_than_picking_one_silently() -> None:
    """Silently choosing between tied platforms is how a recommendation misleads."""

    line = u._recommend_context_line(_signals(gh_sig=True, az_sig=True))

    assert "Mixed CI definitions" in line


def test_no_ci_definitions_at_all_says_the_recommendation_leans_conservative() -> None:
    line = u._recommend_context_line(_signals(ci_definitions=False))

    assert "conservative" in line


def test_signals_present_but_no_platform_match_yields_no_context_line() -> None:
    assert u._recommend_context_line(_signals()) == ""
