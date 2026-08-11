"""What the stdout summary shows when there is no obvious gap, and when a waiver file was used.

"Top gaps" is the part of the summary an operator reads first, so it must not be empty when
the run has something to say. When no individual control produces a usable gap line, the block
falls back to the structural causes -- the buckets that explain *why* controls are failing --
rather than printing a heading with nothing under it.

The waiver note is the honesty half. An external `--waivers` file changes which controls are
suppressed in this run but does not satisfy GOV-WAIV-014, which asks for waivers versioned in
the repository. Saying so on stdout is what stops a green summary from being read as a green
posture.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.application import cli_output
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport


def _report(*, results: list[ControlResult] | None = None, waiver: str | None = None) -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://example/reports/2.0",
        generated_at="2026-08-11T00:00:00Z",
        kit_version="10.0.11",
        target_path="repo",
        profile_id="github-level-1",
        profile_title="T",
        summary_by_status={"pass": 1},
        results=results or [],
        operational_warnings=[],
        weighted_score=None,
        external_waiver_path=waiver,
    )


def _result(control_id: str, status: ControlStatus, reason: str) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        title="t",
        category="governance",
        status=status,
        profile="github-level-1",
        evidence_sources=[],
        confidence="high",
        reason=reason,
        remediation="r",
    )


# --------------------------------------------------------------------------- #
# Gap lines
# --------------------------------------------------------------------------- #


def test_failing_controls_supply_the_gap_lines() -> None:
    report = _report(
        results=[
            _result("GOV-SEC-001", ControlStatus.FAIL, "SECURITY.md not found."),
            _result("GOV-CON-002", ControlStatus.FAIL, "CONTRIBUTING guide not found."),
        ]
    )
    lines = cli_output._collect_gap_lines(report, gap_max=80)
    assert len(lines) == 2
    assert any("SECURITY.md" in line for line in lines)


def test_at_most_three_gap_lines_are_collected() -> None:
    """The summary is a headline, not the report; four bullets is where it stops being one."""

    report = _report(results=[_result(f"GOV-{i:03d}", ControlStatus.FAIL, f"thing {i} not found.") for i in range(6)])
    assert len(cli_output._collect_gap_lines(report, gap_max=80)) == 3


def test_with_no_per_control_gap_the_structural_causes_fill_the_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A heading with nothing under it tells the operator less than the bucket that explains it."""

    monkeypatch.setattr(
        cli_output,
        "compute_priority_insights",
        lambda _r: {
            "top_structural_causes": [
                {"bucket": "Platform settings", "count": 4},
                {"bucket": "Release evidence", "count": 2},
            ],
            "recommended_actions": [],
        },
    )
    lines = cli_output._collect_gap_lines(_report(), gap_max=80)
    assert lines == ["Platform settings (4 control(s))", "Release evidence (2 control(s))"]


def test_the_structural_fallback_also_stops_at_three(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_output,
        "compute_priority_insights",
        lambda _r: {
            "top_structural_causes": [{"bucket": f"Bucket {i}", "count": i} for i in range(6)],
            "recommended_actions": [],
        },
    )
    assert len(cli_output._collect_gap_lines(_report(), gap_max=80)) == 3


def test_a_repeated_structural_bucket_is_listed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_output,
        "compute_priority_insights",
        lambda _r: {
            "top_structural_causes": [
                {"bucket": "Platform settings", "count": 4},
                {"bucket": "Platform settings", "count": 1},
            ],
            "recommended_actions": [],
        },
    )
    assert cli_output._collect_gap_lines(_report(), gap_max=80) == ["Platform settings (4 control(s))"]


# --------------------------------------------------------------------------- #
# Rendering the plain summary
# --------------------------------------------------------------------------- #


def test_a_gap_line_that_wraps_to_nothing_is_skipped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`textwrap.wrap("")` is `[]`; indexing it would raise while printing a summary."""

    monkeypatch.setattr(cli_output, "_collect_gap_lines", lambda *_a, **_k: ["", "SECURITY.md not found."])
    monkeypatch.setattr(
        cli_output,
        "compute_priority_insights",
        lambda _r: {"top_structural_causes": [], "recommended_actions": []},
    )
    cli_output._print_stdout_summary_plain(_report())
    out = capsys.readouterr().out
    assert "SECURITY.md not found." in out
    assert "  - \n" not in out, "an empty bullet was printed"


def test_an_external_waiver_file_is_called_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--waivers` suppresses controls in this run but does not satisfy GOV-WAIV-014."""

    printed: list[Any] = []
    monkeypatch.setattr(cli_output, "print_interactive_stdout_summary", lambda *a, **k: printed.append((a, k)))
    monkeypatch.setattr(cli_output, "human_tty_stdout", lambda: True)

    cli_output.print_stdout_summary(_report(waiver="waivers.yaml"), output_format="human")

    out = capsys.readouterr().out
    assert "GOV-WAIV-014" in out, out


def test_no_external_waiver_prints_no_note(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """The counterpart, so the note cannot appear on every run."""

    monkeypatch.setattr(cli_output, "print_interactive_stdout_summary", lambda *a, **k: None)
    monkeypatch.setattr(cli_output, "human_tty_stdout", lambda: True)

    cli_output.print_stdout_summary(_report(), output_format="human")
    assert "GOV-WAIV-014" not in capsys.readouterr().out
