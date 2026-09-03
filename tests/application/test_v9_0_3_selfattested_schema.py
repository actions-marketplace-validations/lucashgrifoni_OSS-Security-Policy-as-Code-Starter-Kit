"""Regression tests for the v9.0.3 hotfix: SELF_ATTESTED published-schema violation.

Before v9.0.3, ``reporting.REPORTS_V2_STATUS_MAP`` emitted a sixth state
``SELF_ATTESTED`` (reachable on azure/aws evidence paths and via the opt-in
ADR-033 insights wiring) while the packaged reports/2.0 schema forbade it in
BOTH the per-control ``state`` enum and the ``summary_by_status`` key pattern —
so real reports violated their own published schema. v9.0.3 loosens the schema
(strictly: previously-invalid emissions become valid, no valid document becomes
invalid) and fixes the drifted engine status map (missing ``waived``).
"""

from __future__ import annotations

import json

from jsonschema import Draft202012Validator
from tests.conftest import ROOT

from oss_policy_kit.application.reporting import report_to_dict
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

_SCHEMA_PATH = ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "reports" / "2.0.json"


def _result(control_id: str, status: ControlStatus) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        title=control_id,
        category="SA",
        status=status,
        profile="test-profile",
        evidence_sources=[],
        confidence="high",
        reason="self-reported via SECURITY-INSIGHTS.yml",
        remediation="",
    )


def _report_with(statuses: dict[str, ControlStatus]) -> ExecutionReport:
    results = [_result(cid, st) for cid, st in statuses.items()]
    summary: dict[str, int] = {}
    for r in results:
        summary[r.status.value] = summary.get(r.status.value, 0) + 1
    return ExecutionReport(
        schema_version="https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0",
        generated_at="2026-07-01T00:00:00Z",
        kit_version="9.0.3",
        target_path="/tmp/example-repo",
        profile_id="test-profile",
        profile_title="Test profile",
        summary_by_status=summary,
        results=results,
        operational_warnings=[],
    )


def test_self_attested_report_validates_against_published_schema() -> None:
    """A SELF_ATTESTED-bearing report must validate against its own packaged schema."""
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    report = _report_with(
        {
            "GOV-SEC-001": ControlStatus.PASS,
            "AZ-BRPOL-030": ControlStatus.SELF_ATTESTED,
            "SEC-CODEQL-010": ControlStatus.FAIL,
        }
    )
    payload = report_to_dict(report)
    states = {c["state"] for c in payload["controls"]}
    assert "SELF_ATTESTED" in states, "the self-attested control must surface as SELF_ATTESTED"
    assert payload["summary_by_status"].get("SELF_ATTESTED") == 1
    Draft202012Validator(schema).validate(payload)


def test_waived_report_validates_and_maps_reason() -> None:
    """A waived control maps to UNKNOWN with reason 'waived' and validates (v9.0.3 parity fix)."""
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    report = _report_with({"GH-PIN-007": ControlStatus.WAIVED})
    payload = report_to_dict(report)
    control = payload["controls"][0]
    assert control["state"] == "UNKNOWN"
    assert control["reason"] == "waived"
    Draft202012Validator(schema).validate(payload)


def test_migration_block_records_the_removal() -> None:
    """The migration pointer must state the legacy contract was removed (ADR-043)."""
    payload = report_to_dict(_report_with({"GOV-SEC-001": ControlStatus.PASS}))
    migration = payload["migration"]
    assert migration["from"] == "reports/1.0"
    assert "v9.0.0" in migration["removed_in"]
