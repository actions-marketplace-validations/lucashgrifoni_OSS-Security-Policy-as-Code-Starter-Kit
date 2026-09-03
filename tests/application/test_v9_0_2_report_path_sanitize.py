"""Regression: scorecard + external-waiver absolute paths must not leak into shareable reports.

v9.0.2 hotfix (F8): ``_sanitize_target_path_for_payload`` previously governed only
``target_path``. ``scorecard.path``, ``scorecard.supplemental.{path,explanation}``, and
``external_waiver_path`` were written RAW, leaking the auditor's home directory / OS
username into the default JSON and Markdown reports. They must now be basename-sanitized
by default and preserved only when ``include_absolute_path=True``.

The fixtures use a clearly-synthetic absolute root (never a real ``/home`` or user path) so
the assertions can prove the absolute prefix + parent dirs + username segment are stripped.
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application import reporting as rp
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

# Synthetic absolute root: a fake user segment + parent dirs the sanitizer must strip.
_ABS_ROOT = "/synthetic-abs-root/ci-user/secret-repo"
_ABS_SCORECARD = _ABS_ROOT + "/scorecard.json"
_ABS_WAIVER = _ABS_ROOT + "/waivers/waivers.yaml"
_USERNAME = "ci-user"


def _report() -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-06-29T00:00:00Z",
        kit_version="9.0.2",
        target_path=_ABS_ROOT,
        profile_id="github-level-3",
        profile_title="Title",
        summary_by_status={"pass": 1, "fail": 1},
        results=[
            ControlResult(
                control_id="GOV-SEC-001",
                title="t",
                category="governance",
                status=ControlStatus.PASS,
                profile="github-level-3",
                evidence_sources=[],
                confidence="high",
                reason="ok",
                remediation="keep",
            ),
            ControlResult(
                control_id="SEC-CODEQL-010",
                title="sast",
                category="security",
                status=ControlStatus.FAIL,
                profile="github-level-3",
                evidence_sources=[],
                confidence="medium",
                reason="missing",
                remediation="add codeql",
            ),
        ],
        operational_warnings=[],
        scorecard_path=_ABS_SCORECARD,
        scorecard_supplemental={
            "loaded": True,
            "path": _ABS_SCORECARD,
            "check_count": 3,
            "influenced_control_ids": [],
            "workflows_satisfied_codeql_signal": False,
            "explanation": f"Loaded 3 scorecard check entr(y/ies) from {_ABS_SCORECARD}.",
        },
        external_waiver_path=_ABS_WAIVER,
    )


def _assert_no_leak(blob: str) -> None:
    assert _USERNAME not in blob, "OS username segment leaked into shareable report"
    assert "/synthetic-abs-root/" not in blob, "absolute root prefix leaked into shareable report"
    assert "secret-repo/" not in blob, "parent directories leaked into shareable report"


def test_json_default_sanitizes_scorecard_and_waiver_paths() -> None:
    payload = rp.report_to_dict(_report())

    assert payload["scorecard"]["path"] == "scorecard.json"
    assert payload["scorecard"]["supplemental"]["path"] == "scorecard.json"
    assert payload["external_waiver_path"] == "waivers.yaml"

    # The embedded path inside the explanation must also be sanitized, prose preserved.
    explanation = payload["scorecard"]["supplemental"]["explanation"]
    assert "scorecard.json" in explanation
    assert explanation.startswith("Loaded 3 scorecard check entr(y/ies) from ")

    import json

    _assert_no_leak(json.dumps(payload))


def test_json_include_absolute_path_preserves_absolute_paths() -> None:
    payload = rp.report_to_dict(_report(), include_absolute_path=True)

    assert payload["scorecard"]["path"] == _ABS_SCORECARD
    assert payload["scorecard"]["supplemental"]["path"] == _ABS_SCORECARD
    assert payload["external_waiver_path"] == _ABS_WAIVER
    assert _ABS_SCORECARD in payload["scorecard"]["supplemental"]["explanation"]


def test_markdown_default_sanitizes_scorecard_and_waiver_paths(tmp_path: Path) -> None:
    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(_report(), md)
    text = md.read_text(encoding="utf-8")

    assert "`scorecard.json`" in text
    assert "`waivers.yaml`" in text
    _assert_no_leak(text)


def test_markdown_include_absolute_path_preserves_absolute_paths(tmp_path: Path) -> None:
    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(_report(), md, include_absolute_path=True)
    text = md.read_text(encoding="utf-8")

    assert _ABS_SCORECARD in text
    assert _ABS_WAIVER in text
