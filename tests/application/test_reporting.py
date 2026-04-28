"""Report serialization."""

import json
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import (
    REPORT_JSON_SCHEMA_URL_V0_1,
    REPORT_JSON_SCHEMA_URL_V0_3,
    evaluate_repository,
)
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict, write_reports


def test_json_report_shape(tmp_path: Path) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    write_reports(report, tmp_path)
    payload = json.loads((tmp_path / "evaluation-report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"]
    assert payload["summary_by_status"]
    assert isinstance(payload["results"], list)
    row0 = payload["results"][0]
    for key in (
        "control_id",
        "title",
        "category",
        "status",
        "profile",
        "evidence_sources",
        "confidence",
        "reason",
        "remediation",
        "evidence_collection_method",
    ):
        assert key in row0
    assert "live_collection" in payload
    assert payload["schema_version"] == REPORT_JSON_SCHEMA_URL_V0_3
    assert "summary_by_gate_role" in payload
    assert "gate_execution_model" in payload


def test_report_to_dict_schema_override_emits_v0_1_shape(tmp_path) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        report_json_contract="0.2",
    )
    payload = report_to_dict(report, schema_version_override="reports/0.1")
    assert payload["schema_version"] == REPORT_JSON_SCHEMA_URL_V0_1
    assert "live_collection" not in payload
    row0 = payload["results"][0]
    assert "evidence_collection_method" not in row0


def test_report_json_contract_0_2_omits_v0_3_gate_fields() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        report_json_contract="0.2",
    )
    d = report_to_dict(report)
    assert "reports/0.2" in d["schema_version"]
    assert "summary_by_gate_role" not in d
    assert "gate_execution_model" not in d


def test_report_to_dict_roundtrip_keys() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    d = report_to_dict(report)
    assert set(d["summary_by_status"].keys()) <= {
        "pass",
        "fail",
        "manual-review-required",
        "self-attested",
        "not-evaluated",
        "not-observable",
        "not-applicable",
        "waived",
    }
