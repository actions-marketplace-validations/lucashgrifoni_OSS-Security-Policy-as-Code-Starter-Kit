"""reports/2.0 contract URL + status mapping (PR-16, V6-05, ADR-013)."""

from __future__ import annotations

import pytest
from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import (
    REPORT_JSON_SCHEMA_URL_V2_0,
    evaluate_repository,
    map_status_to_reports_v2,
    report_json_schema_url,
)
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict
from oss_policy_kit.domain.errors import LoadError

# --- URL constants + resolver ----------------------------------------------


def test_v2_url_is_reports_2_0() -> None:
    assert REPORT_JSON_SCHEMA_URL_V2_0.endswith("/reports/2.0")


def test_resolver_accepts_2_0() -> None:
    assert report_json_schema_url("2.0") == REPORT_JSON_SCHEMA_URL_V2_0


def test_resolver_default_is_2_0() -> None:
    """reports/2.0 is the only contract (ADR-043, v9.0.0): a removed legacy contract
    (e.g. 1.0) is a hard error, and a blank value fails closed instead of silently
    mapping to the default (9.0.1: the default is the explicit '2.0' Option default)."""
    with pytest.raises(LoadError, match=r"removed in v9.0.0"):
        report_json_schema_url("1.0")
    with pytest.raises(LoadError):
        report_json_schema_url("")


def test_resolver_unknown_mentions_2_0_in_error() -> None:
    with pytest.raises(LoadError, match=r"2\.0"):
        report_json_schema_url("9.9")


# --- Status mapping --------------------------------------------------------


@pytest.mark.parametrize(
    "v1_status,expected_state,expected_reason",
    [
        ("pass", "PASS", None),
        ("fail", "FAIL", None),
        ("degraded", "FAIL", None),
        ("manual-review-required", "UNKNOWN", "manual-review-required"),
        ("not-applicable", "NOT_APPLICABLE", None),
        ("skipped", "UNKNOWN", "skipped-by-flag"),
        ("error", "UNKNOWN", "evaluator-error"),
        ("attested", "ATTESTED", None),
    ],
)
def test_status_mapping_matches_adr_table(v1_status: str, expected_state: str, expected_reason: str | None) -> None:
    state, reason = map_status_to_reports_v2(v1_status)
    assert state == expected_state
    assert reason == expected_reason


def test_status_mapping_handles_unknown_value() -> None:
    state, reason = map_status_to_reports_v2("brand-new-status")
    assert state == "UNKNOWN"
    assert reason == "unmapped-source-status"


def test_status_mapping_case_insensitive() -> None:
    assert map_status_to_reports_v2("PASS") == ("PASS", None)
    assert map_status_to_reports_v2("Manual-Review-Required") == ("UNKNOWN", "manual-review-required")


def test_evaluate_report_contract_2_0_emits_projected_controls() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        report_json_contract="2.0",
    )
    out = report_to_dict(report)
    assert out["schema_version"] == REPORT_JSON_SCHEMA_URL_V2_0
    assert out["contract_version"] == "reports/2.0"
    assert "controls" in out
    assert "results" not in out
    # Full reports/2.0 state vocabulary (six states since v9.0.3: SELF_ATTESTED formalized).
    states = {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "ATTESTED", "SELF_ATTESTED"}
    assert set(out["summary_by_status"]) <= states
    first = out["controls"][0]
    assert "state" in first
    assert first["state"] in states
    assert "message" in first
