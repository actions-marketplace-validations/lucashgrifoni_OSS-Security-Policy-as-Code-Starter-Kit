"""The terminal_ui paths that only run when the environment refuses something.

Every case here is a degraded environment rather than an exotic one: a console that
refuses colour (``NO_COLOR``, a dumb terminal, a pipe), a codepage that cannot encode the
banner glyphs, a Typer build without ``rich_utils``, a window too narrow for the health
strip, and a run whose only blockers are manual reviews rather than failures.

They matter because each one is a *fallback*. If the no-colour branch is wrong the banner
prints escape codes into a log file; if the ASCII branch is wrong the CLI dies with
``UnicodeEncodeError`` while merely trying to draw its own name; if the ``rich_utils``
import guard is wrong ``--help`` stops working. None of that shows up on a developer
machine with a modern terminal, which is exactly why it needs pinning.

The layout assertions state invariants instead of exact integers, matching the convention in
``test_terminal_ui_degradation.py``: the percentages are meant to be tuned. The invariant is
that the columns spend the usable width exactly once the window can hold every minimum, and
park at the sum of those minimums below that -- not that they always fit, which is false
under about 63 columns and is where Rich starts wrapping instead.
"""

from __future__ import annotations

import builtins
import sys
from io import StringIO
from types import SimpleNamespace
from typing import Any

import pytest
from rich.console import Console

from oss_policy_kit.cli import terminal_ui as tui
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport


def _console(width: int = 100, *, no_color: bool = False) -> tuple[Console, StringIO]:
    buf = StringIO()
    return (
        Console(file=buf, width=width, force_terminal=False, color_system=None, no_color=no_color),
        buf,
    )


def _manual_only_report() -> ExecutionReport:
    """A run with no failures but an outstanding manual review."""

    return ExecutionReport(
        schema_version="https://example/reports/2.0",
        generated_at="2026-04-18T00:00:00Z",
        kit_version="10.0.10",
        target_path="/tmp/repo",
        profile_id="github-level-1",
        profile_title="Title",
        summary_by_status={"pass": 3, "manual-review-required": 1},
        results=[
            ControlResult(
                control_id="GOV-MR-002",
                title="Manual thing",
                category="governance",
                status=ControlStatus.MANUAL_REVIEW_REQUIRED,
                profile="github-level-1",
                evidence_sources=[],
                confidence="low",
                reason="Check it.",
                remediation="Do.",
            )
        ],
        operational_warnings=[],
        weighted_score=None,
    )


# --------------------------------------------------------------------------- #
# Narrow-window layout arithmetic
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("detailed", [True, False])
def test_profile_layout_at_the_narrowest_window_keeps_every_minimum(detailed: bool) -> None:
    """The squeeze path runs only below ~40 columns, and must not starve a column."""

    layout = tui.profile_table_layout_for_width(terminal_columns=38, detailed=detailed, longest_profile_id_chars=0)
    assert layout.profile >= tui._PROFILE_COL_MIN_PROFILE
    assert layout.title >= tui._PROFILE_COL_MIN_TITLE
    assert layout.audience >= tui._PROFILE_COL_MIN_AUDIENCE
    assert layout.description >= tui._PROFILE_COL_MIN_DESCRIPTION


def test_profile_layout_spends_the_window_exactly_once_it_fits_the_minimums() -> None:
    """Above the minimum-sum floor the columns spend the usable width exactly, never more.

    Below that floor the minimums win and the total stays parked at the floor: the columns
    do not shrink past what each one needs, and Rich wraps instead. Asserting ``<= usable``
    would encode the opposite rule and fail on any window under ~63 columns.
    """

    floor = (
        tui._PROFILE_COL_MIN_PROFILE
        + tui._PROFILE_COL_MIN_TITLE
        + tui._PROFILE_PLATFORM_COL_WIDTH
        + tui._PROFILE_LEVEL_COL_WIDTH
        + tui._PROFILE_GATE_COL_WIDTH
        + tui._PROFILE_COL_MIN_AUDIENCE
        + tui._PROFILE_COL_MIN_DESCRIPTION
    )
    for tc in (38, 40, 55, 80, 120, 200, 512, 4096):
        layout = tui.profile_table_layout_for_width(terminal_columns=tc, detailed=False, longest_profile_id_chars=24)
        usable = max(40, max(40, min(tc, tui.MAX_COLUMNS)) - tui.PROFILE_TABLE_OVERHEAD_COLUMNS)
        total = (
            layout.profile
            + layout.title
            + layout.platform
            + layout.level
            + layout.gate
            + layout.audience
            + layout.description
        )
        assert total == max(usable, floor), f"columns do not add up at {tc} columns"


# --------------------------------------------------------------------------- #
# Banner gating
# --------------------------------------------------------------------------- #


def test_banner_is_suppressed_when_neither_stdout_nor_stderr_is_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fully redirected run (``cmd > out.txt 2> err.txt``): no banner, no width probe."""

    monkeypatch.setattr(tui, "is_interactive_stream", lambda _s: False)
    monkeypatch.setattr(tui, "terminal_width", lambda _s: pytest.fail("width probed with no interactive stream"))
    assert tui.should_show_cli_banner() is False


def test_banner_uses_the_widest_interactive_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    """stderr may be a wide TTY while stdout is piped; the wider one decides."""

    monkeypatch.setattr(tui, "is_interactive_stream", lambda _s: True)
    widths = {id(sys.stdout): 10, id(sys.stderr): tui.CLI_BANNER_MIN_COLUMNS + 5}
    monkeypatch.setattr(tui, "terminal_width", lambda s: widths.get(id(s), 10))
    assert tui.should_show_cli_banner() is True

    monkeypatch.setattr(tui, "terminal_width", lambda _s: tui.CLI_BANNER_MIN_COLUMNS - 1)
    assert tui.should_show_cli_banner() is False


# --------------------------------------------------------------------------- #
# Typer rich_utils fallbacks
# --------------------------------------------------------------------------- #


def _block_typer_rich_utils(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``from typer import rich_utils`` raise, as on a Typer built without Rich."""

    real_import = builtins.__import__

    def fake_import(name: str, globals_: Any = None, locals_: Any = None, fromlist: Any = (), level: int = 0) -> Any:
        if name == "typer" and fromlist and "rich_utils" in fromlist:
            raise ImportError("no rich_utils in this Typer build")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_banner_is_skipped_when_typer_has_no_rich_utils(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Typer without ``rich_utils`` must lose the banner, not the command."""

    monkeypatch.setattr(tui, "should_show_cli_banner", lambda **_k: True)
    _block_typer_rich_utils(monkeypatch)
    assert tui.print_cli_banner_before_typer_rich_help() is None


def test_help_epilog_falls_back_to_the_plain_stdout_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same missing import, on the epilog path: fall back rather than raise."""

    _block_typer_rich_utils(monkeypatch)
    assert isinstance(tui._help_epilog_console(), Console)


def test_banner_drops_styling_when_the_console_refuses_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    """NO_COLOR / dumb terminal / pipe: plain text, no markup, no escape codes."""

    from typer import rich_utils as typer_rich_utils

    console, buf = _console(width=120, no_color=True)
    monkeypatch.setattr(tui, "should_show_cli_banner", lambda **_k: True)
    monkeypatch.setattr(tui, "stream_supports_unicode", lambda _s: True)
    monkeypatch.setattr(typer_rich_utils, "_get_rich_console", lambda stderr=False: console)

    tui.print_cli_banner_before_typer_rich_help()

    out = buf.getvalue()
    assert out.strip(), "the banner must still be printed without colour"
    assert "\x1b[" not in out, "no-colour console must not emit escape sequences"


def test_banner_keeps_ascii_art_when_the_codepage_cannot_encode_glyphs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy codepage with colour available: keep colour off the art, keep ASCII."""

    from typer import rich_utils as typer_rich_utils

    console, buf = _console(width=120)
    monkeypatch.setattr(tui, "should_show_cli_banner", lambda **_k: True)
    monkeypatch.setattr(tui, "stream_supports_unicode", lambda _s: False)
    monkeypatch.setattr(typer_rich_utils, "_get_rich_console", lambda stderr=False: console)

    tui.print_cli_banner_before_typer_rich_help()

    out = buf.getvalue()
    assert out.strip(), "the ASCII banner must still be printed"
    assert out == out.encode("ascii", "replace").decode("ascii"), "art must stay ASCII-encodable"


# --------------------------------------------------------------------------- #
# Panels that degrade on narrow windows / manual-only outcomes
# --------------------------------------------------------------------------- #


def test_health_strip_is_dropped_when_the_panel_is_too_narrow_to_hold_a_bar() -> None:
    """Below the bar's minimum the strip prints nothing rather than a broken bar."""

    console, buf = _console(width=10)
    tui._print_health_strip(console, pass_n=1, fail_n=1, manual_n=1, unicode_icons=False, w=10)
    assert buf.getvalue() == ""


def test_executive_preface_reads_attention_when_only_manual_reviews_remain() -> None:
    """No failures but an open manual review is 'attention', never 'healthy'."""

    console, buf = _console(width=100)
    tui.print_evaluate_executive_preface(_manual_only_report(), unicode_icons=False, console=console)
    out = buf.getvalue()
    assert "attention" in out
    assert "healthy" not in out


def test_interactive_summary_reads_attention_when_only_manual_reviews_remain() -> None:
    """The stdout summary has its own copy of the same wording; pin it too."""

    console, buf = _console(width=100)
    tui.print_interactive_stdout_summary(
        _manual_only_report(), gap_lines=[], next_step="Do the review.", console=console
    )
    out = buf.getvalue()
    assert "attention" in out
    assert "healthy" not in out


# --------------------------------------------------------------------------- #
# recommend-profile panels
# --------------------------------------------------------------------------- #


def test_recommend_scope_explains_why_release_evidence_is_only_partial() -> None:
    """CI definitions but no evidence JSON: say what would make it strong."""

    sig = tui._RecSignals(
        gh="-",
        az="-",
        aws="-",
        gh_sig=True,
        az_sig=False,
        aws_sig=False,
        gh_ev=False,
        az_ev=False,
        aws_ev=False,
        rel_label="partial",
        ci_definitions=True,
    )
    text = tui._build_recommend_scope(sig, compact=False).plain
    assert "partial" in text
    assert ".oss-policy-kit/evidence" in text


def test_recommend_decision_omits_empty_sections_and_still_offers_the_runner_up() -> None:
    """No rationale and no context line: those headings disappear, 'Also consider' stays."""

    suggestions: list[dict[str, Any]] = [
        {"profile_id": "custom-alpha"},
        {"profile_id": "custom-beta"},
    ]
    text = tui._build_recommend_decision(suggestions, "").plain

    assert "custom-alpha" in text
    assert "Why now" not in text, "no rationale means no 'Why now' heading"
    assert "Recommendation path" not in text, "empty context line means no path heading"
    assert "Also consider" in text
    assert "custom-beta" in text


def test_observed_signals_reports_how_many_it_truncated() -> None:
    """More than eight signals: the reader is told the list was cut, and by how much."""

    console, buf = _console(width=100)
    rec = SimpleNamespace(signals_detected=[{"id": f"SIG-{i}", "detail": "detail"} for i in range(11)])
    tui._print_observed_signals(console, rec, 100, unicode_icons=False)
    out = buf.getvalue()
    assert "3 more" in out, "11 signals minus the 8 shown is 3"
