"""Unit tests for CLI output helpers."""

from __future__ import annotations

import json
from io import StringIO
from typing import cast

import pytest

from oss_policy_kit.application.cli_output import fail_on_violated, print_stdout_summary
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport


@pytest.mark.parametrize(
    ("policy", "summary", "expected"),
    [
        ("none", {"fail": 3}, False),
        ("fail", {"fail": 0}, False),
        ("fail", {"fail": 1}, True),
        ("degraded", {"fail": 0, "manual-review-required": 1}, True),
        ("degraded", {"fail": 0, "pass": 14}, False),
    ],
)
def test_fail_on_violated(policy: str, summary: dict[str, int], expected: bool) -> None:
    assert fail_on_violated(policy, summary) is expected


def _report_with_summary(summary: dict[str, int]) -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://example/reports/0.1",
        generated_at="2026-01-01T00:00:00Z",
        kit_version="1.0.2",
        target_path="repo-under-test",
        profile_id="github-level-1",
        profile_title="GitHub Level 1",
        summary_by_status=summary,
        results=[],
        operational_warnings=[],
    )


def test_print_stdout_summary_human_includes_canonical_order_and_total(capsys: pytest.CaptureFixture[str]) -> None:
    report = _report_with_summary({"manual-review-required": 2, "pass": 10, "fail": 1})
    print_stdout_summary(report, output_format="human")
    out = capsys.readouterr().out.strip()
    assert "Profile: github-level-1" in out
    assert "Target: repo-under-test" in out
    assert "fail=1" in out
    assert "pass=10" in out
    assert "manual-review-required=2" in out
    assert "Top gaps:" in out
    assert "Suggested next step:" in out


def test_print_stdout_summary_top_gaps_use_reason_not_positive_title(capsys: pytest.CaptureFixture[str]) -> None:
    """Failed controls must not list catalog titles that read like successes."""

    fail_row = ControlResult(
        control_id="GOV-SEC-001",
        title="SECURITY.md present",
        category="governance",
        status=ControlStatus.FAIL,
        profile="github-level-1",
        evidence_sources=[],
        confidence="high",
        reason="SECURITY.md not found at repository root.",
        remediation="Add SECURITY.md.",
    )
    report = ExecutionReport(
        schema_version="https://example/reports/0.1",
        generated_at="2026-01-01T00:00:00Z",
        kit_version="1.0.2",
        target_path="repo-under-test",
        profile_id="github-level-1",
        profile_title="GitHub Level 1",
        summary_by_status={"fail": 1},
        results=[fail_row],
        operational_warnings=[],
    )
    print_stdout_summary(report, output_format="human")
    out = capsys.readouterr().out
    assert "Top gaps:" in out
    assert "SECURITY.md not found" in out
    assert "SECURITY.md present" not in out


def test_print_stdout_summary_json_includes_total_and_order() -> None:
    report = _report_with_summary({"manual-review-required": 2, "pass": 10, "fail": 1})
    fake_stdout = StringIO()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("sys.stdout", cast("StringIO", fake_stdout))
        print_stdout_summary(report, output_format="json")
    payload = json.loads(fake_stdout.getvalue())
    assert list(payload["summary_by_status"].keys()) == ["pass", "fail", "manual-review-required"]
    assert payload["controls_total"] == 13
