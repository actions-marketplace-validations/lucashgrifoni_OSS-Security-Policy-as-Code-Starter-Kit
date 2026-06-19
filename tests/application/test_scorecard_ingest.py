"""Unit tests for the Scorecard ingest crosswalk + freshness (T2.3, single source of truth)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from oss_policy_kit.adapters.scorecard_json import load_scorecard_auto
from oss_policy_kit.application.scorecard_ingest import (
    SCORECARD_CONTROL_MAP,
    build_report,
    ingest_scorecard,
)

# A Scorecard v5.x --format json shape (top-level date/score/checks).
_FIXTURE = {
    "date": "2026-06-01T00:00:00Z",
    "repo": {"name": "github.com/x/y"},
    "scorecard": {"version": "v5.1.0", "commit": "abc"},
    "score": 7.3,
    "checks": [
        {"name": "Token-Permissions", "score": 9, "reason": "tokens are read-only"},
        {"name": "Branch-Protection", "score": 8, "reason": "protected"},
        {"name": "Pinned-Dependencies", "score": 7, "reason": "mostly pinned"},
        {"name": "Code-Review", "score": 10, "reason": "all reviewed"},
        {"name": "SAST", "score": 6, "reason": "codeql present"},
        {"name": "License", "score": 10, "reason": "license found"},
        {"name": "Dangerous-Workflow", "score": 10, "reason": "no dangerous patterns"},
    ],
}
_FRESH = datetime(2026, 6, 15, tzinfo=UTC)  # 14 days after the result
_STALE = datetime(2026, 10, 1, tzinfo=UTC)  # >90 days after the result


def _write_fixture(tmp_path: Path, data: dict[str, object] | None = None) -> Path:
    path = tmp_path / "scorecard-result.json"
    path.write_text(json.dumps(data if data is not None else _FIXTURE), encoding="utf-8")
    return path


def test_crosswalk_has_at_least_six_mappings() -> None:
    assert len(SCORECARD_CONTROL_MAP) >= 6
    # No duplicate Scorecard checks; every row carries a control id.
    checks = [c for c, _, _ in SCORECARD_CONTROL_MAP]
    assert len(checks) == len(set(checks))
    assert all(control for _, control, _ in SCORECARD_CONTROL_MAP)


def test_present_and_absent_checks(tmp_path: Path) -> None:
    report = ingest_scorecard(_write_fixture(tmp_path), now=_FRESH)
    assert len(report.mapped) == len(SCORECARD_CONTROL_MAP)
    present = {m.scorecard_check for m in report.present_checks}
    assert {"Token-Permissions", "SAST", "Dangerous-Workflow"} <= present
    # Fuzzing is in the crosswalk but absent from the fixture -> present False, no score.
    fuzz = next(m for m in report.mapped if m.scorecard_check == "Fuzzing")
    assert fuzz.present is False and fuzz.score is None


def test_scores_recorded_verbatim(tmp_path: Path) -> None:
    report = ingest_scorecard(_write_fixture(tmp_path), now=_FRESH)
    sast = next(m for m in report.mapped if m.scorecard_check == "SAST")
    assert sast.score == 6 and sast.control_id == "SEC-CODEQL-010"  # verbatim, mapped to CodeQL control
    assert report.aggregate_score == 7.3


def test_fresh_result_corroborates_present_controls(tmp_path: Path) -> None:
    report = ingest_scorecard(_write_fixture(tmp_path), now=_FRESH)
    assert report.freshness == "fresh"
    assert "CI-PERM-006" in report.corroborated_controls  # Token-Permissions present + fresh
    assert "SEC-FUZZ-001" not in report.corroborated_controls  # Fuzzing absent


def test_stale_result_corroborates_nothing(tmp_path: Path) -> None:
    report = ingest_scorecard(_write_fixture(tmp_path), now=_STALE)
    assert report.freshness == "stale"
    assert report.corroborated_controls == ()


def test_undated_result_is_undated(tmp_path: Path) -> None:
    data = dict(_FIXTURE)
    data.pop("date")
    report = ingest_scorecard(_write_fixture(tmp_path, data), now=_FRESH)
    assert report.freshness == "undated"
    assert report.corroborated_controls == ()


def test_to_dict_is_json_serializable_and_honest(tmp_path: Path) -> None:
    report = ingest_scorecard(_write_fixture(tmp_path), now=_FRESH)
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["freshness"] == "fresh"
    assert payload["aggregate_score"] == 7.3
    assert "CI-PERM-006" in payload["corroborated_controls"]
    # never exposes an "evidence_backed" key — corroboration is inferred-trust signal only.
    assert "evidence_backed_controls" not in payload
    assert len(payload["mapped_checks"]) == len(SCORECARD_CONTROL_MAP)


def test_build_report_from_bundle(tmp_path: Path) -> None:
    bundle = load_scorecard_auto(_write_fixture(tmp_path))
    report = build_report(bundle, input_path="x.json", now=_FRESH)
    assert report.result_date == "2026-06-01T00:00:00Z"
    assert report.input_path == "x.json"
