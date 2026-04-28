"""Tests for centralized terminal width and profile table layout helpers."""

from __future__ import annotations

import io
from os import terminal_size
from unittest.mock import MagicMock

import pytest

from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport


def test_terminal_width_non_tty_uses_fallback() -> None:
    assert terminal_ui.terminal_width(io.StringIO()) == terminal_ui.DEFAULT_FALLBACK_COLUMNS


def test_terminal_width_non_tty_custom_fallback() -> None:
    assert terminal_ui.terminal_width(io.StringIO(), fallback=80) == 80


def test_terminal_width_tty_uses_get_terminal_size(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_out = MagicMock()
    fake_out.isatty.return_value = True

    def _fake_get_terminal_size(*, fallback: object = (80, 24)) -> terminal_size:
        _ = fallback
        return terminal_size((132, 40))

    monkeypatch.setattr(terminal_ui.sys, "stdout", fake_out)
    monkeypatch.setattr(terminal_ui, "_get_terminal_size", _fake_get_terminal_size)
    assert terminal_ui.terminal_width(fake_out) == 132


def test_terminal_width_tty_caps_max(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_out = MagicMock()
    fake_out.isatty.return_value = True

    def _huge(*, fallback: object = (80, 24)) -> terminal_size:
        _ = fallback
        return terminal_size((900, 60))

    monkeypatch.setattr(terminal_ui.sys, "stdout", fake_out)
    monkeypatch.setattr(terminal_ui, "_get_terminal_size", _huge)
    assert terminal_ui.terminal_width(fake_out) == terminal_ui.MAX_COLUMNS


def test_terminal_width_oserror_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_out = MagicMock()
    fake_out.isatty.return_value = True

    def _boom(*, fallback: object = (80, 24)) -> terminal_size:
        _ = fallback
        raise OSError("no tty")

    monkeypatch.setattr(terminal_ui.sys, "stdout", fake_out)
    monkeypatch.setattr(terminal_ui, "_get_terminal_size", _boom)
    assert terminal_ui.terminal_width(fake_out) == terminal_ui.DEFAULT_FALLBACK_COLUMNS


@pytest.mark.parametrize(
    ("term_cols", "detailed", "longest_pid"),
    [
        (72, False, 22),
        (120, False, 27),
        (200, True, 27),
    ],
)
def test_profile_table_layout_positive_widths(
    term_cols: int,
    detailed: bool,
    longest_pid: int,
) -> None:
    layout = terminal_ui.profile_table_layout_for_width(
        terminal_columns=term_cols,
        detailed=detailed,
        longest_profile_id_chars=longest_pid,
    )
    for name, w in (
        ("profile", layout.profile),
        ("title", layout.title),
        ("platform", layout.platform),
        ("level", layout.level),
        ("audience", layout.audience),
        ("description", layout.description),
    ):
        assert w >= 1, name
    assert layout.platform == 8
    assert layout.level == 5


def test_profile_table_layout_detailed_allocates_more_to_description_than_compact() -> None:
    term = 140
    pid = 27
    compact = terminal_ui.profile_table_layout_for_width(
        terminal_columns=term, detailed=False, longest_profile_id_chars=pid
    )
    detailed = terminal_ui.profile_table_layout_for_width(
        terminal_columns=term, detailed=True, longest_profile_id_chars=pid
    )
    assert detailed.description >= compact.description
    assert (
        compact.title + compact.audience + compact.description
        == detailed.title + detailed.audience + detailed.description
    )


def test_profile_table_layout_sum_fits_usable_width() -> None:
    term = 100
    layout = terminal_ui.profile_table_layout_for_width(
        terminal_columns=term,
        detailed=True,
        longest_profile_id_chars=27,
    )
    usable = term - terminal_ui.PROFILE_TABLE_OVERHEAD_COLUMNS
    total = layout.profile + layout.title + layout.platform + layout.level + layout.audience + layout.description
    assert total <= usable + 1


def test_build_stdout_console_respects_explicit_width() -> None:
    c = terminal_ui.build_stdout_console(width=88)
    assert abs(c.width - 88) <= 2


def test_human_fill_wraps_when_terminal_width_is_narrow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(terminal_ui, "terminal_width", lambda _s, fallback=120: 28)
    out = terminal_ui.human_fill("one two three four five six seven eight", stream=io.StringIO())
    assert "\n" in out


def _sample_report() -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://example/reports/0.2",
        generated_at="2026-04-18T00:00:00Z",
        kit_version="3.0.0",
        target_path="C:/tmp/repo",
        profile_id="github-level-1",
        profile_title="GitHub Level 1",
        summary_by_status={"pass": 1, "fail": 1},
        results=[
            ControlResult(
                control_id="GOV-SEC-001",
                title="SECURITY.md present",
                category="governance",
                status=ControlStatus.PASS,
                profile="github-level-1",
                evidence_sources=[],
                confidence="high",
                reason="Found file.",
                remediation="Keep it updated.",
            ),
            ControlResult(
                control_id="CI-PIN-008",
                title="Third-party actions pinned",
                category="supply_chain",
                status=ControlStatus.FAIL,
                profile="github-level-1",
                evidence_sources=[],
                confidence="medium",
                reason="Mutable refs detected.",
                remediation="Pin SHAs.",
            ),
        ],
        operational_warnings=[],
    )


def test_stream_supports_unicode_false_for_cp1252() -> None:
    class _FakeStream:
        encoding = "cp1252"

    fake = _FakeStream()
    assert terminal_ui.stream_supports_unicode(fake) is False


def test_render_eval_results_table_ascii_icons_when_unicode_disabled() -> None:
    table = terminal_ui.render_eval_results_table(_sample_report(), unicode_icons=False)
    status_cells = [column._cells for column in table.columns][1]
    assert status_cells == ["[green]+ pass[/green]", "[red]x fail[/red]"]
