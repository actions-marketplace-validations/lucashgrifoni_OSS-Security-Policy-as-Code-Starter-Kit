"""Coverage for ``application.reporting`` serialization (reports/2.0 only) + profile helpers."""

from __future__ import annotations

from oss_policy_kit.application import reporting as rp
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, WeightedScore


def _report(profile_id: str = "github-level-3", schema: str = "https://x/reports/2.0") -> ExecutionReport:
    return ExecutionReport(
        schema_version=schema,
        generated_at="2026-04-18T00:00:00Z",
        kit_version="6.1.0",
        target_path="C:/tmp/repo",
        profile_id=profile_id,
        profile_title="Title",
        summary_by_status={"pass": 2, "fail": 1, "manual-review-required": 1},
        results=[
            ControlResult(
                control_id="GOV-SEC-001",
                title="t",
                category="governance",
                status=ControlStatus.PASS,
                profile=profile_id,
                evidence_sources=[],
                confidence="high",
                reason="ok",
                remediation="keep",
            ),
            ControlResult(
                control_id="CI-PIN-008",
                title="pin",
                category="supply_chain",
                status=ControlStatus.FAIL,
                profile=profile_id,
                evidence_sources=[],
                confidence="medium",
                reason="bad",
                remediation="pin",
            ),
        ],
        operational_warnings=[],
        weighted_score=WeightedScore(earned=7, possible=10, percent=70.0),
    )


def test_map_status_to_reports_v2() -> None:
    state, _ = rp._map_status_to_reports_v2("pass")
    assert isinstance(state, str)
    unknown, reason = rp._map_status_to_reports_v2("totally-unknown")
    assert unknown == "UNKNOWN"
    assert reason == "unmapped-source-status"


def test_profile_helpers() -> None:
    assert rp._profile_family("github-level-1") == "github"
    assert rp._profile_family("azure-x") == "azure"
    assert rp._profile_family("aws-x") == "aws"
    assert rp._profile_family("custom") is None
    assert rp._profile_level("github-level-2") == "L2"
    assert rp._profile_posture("github-level-3") == "hard_gate"
    assert rp._profile_posture("github-level-1") == "starter"
    assert rp._profile_posture("github-level-2") == "advisory"
    assert rp._profile_posture("github-aws-level-2") == "multi_platform_advisory_hybrid"


def test_derive_profile_metadata_and_digest() -> None:
    meta = rp.derive_profile_metadata("github-level-3")
    assert meta["family"] == "github"
    assert meta["posture"] == "hard_gate"
    digest = rp.compute_results_digest(_report().results)
    assert isinstance(digest, str)
    assert len(digest) >= 8


def test_report_to_dict_default_is_v2_0() -> None:
    payload = rp.report_to_dict(_report())
    assert payload["profile"]["id"] == "github-level-3"
    assert "controls" in payload
    assert "action_insights" in payload
    assert payload["contract_version"] == "reports/2.0"


def test_report_to_dict_v2_0_shape() -> None:
    payload = rp.report_to_dict(_report(), schema_version_override="https://x/reports/2.0")
    assert isinstance(payload, dict)
    assert "controls" in payload
    assert payload["profile"]["family"] == "github"
    assert payload["weighted_score"]["percent"] == 70.0


def test_report_to_dict_direct_absolute_path() -> None:
    payload = rp.report_to_dict(_report(), include_absolute_path=True)
    assert payload["results_digest"]
    assert payload["controls_total"] == 4
