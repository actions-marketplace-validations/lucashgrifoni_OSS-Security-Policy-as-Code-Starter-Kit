"""Report serialization (reports/2.0 — the only contract since v9.0.0, ADR-043)."""

import json
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import REPORT_JSON_SCHEMA_URL_V2_0, evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict, write_reports


def _evaluate(profile_id: str = "github-level-1"):
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    return evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )


def test_json_report_shape(tmp_path: Path) -> None:
    write_reports(_evaluate(), tmp_path)
    payload = json.loads((tmp_path / "evaluation-report.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == REPORT_JSON_SCHEMA_URL_V2_0
    assert payload["contract_version"] == "reports/2.0"
    assert payload["summary_by_status"]
    assert isinstance(payload["controls"], list)
    row0 = payload["controls"][0]
    for key in (
        "id",
        "title",
        "category",
        "lifecycle",
        "profile",
        "state",
        "assurance",
        "confidence",
        "weight",
        "message",
        "remediation",
        "evidence",
    ):
        assert key in row0
    assert "live_collection" in payload
    # reports/2.0 has no gate-role / gate-execution-model fields (those were reports/0.3 & 1.0 only).
    assert "summary_by_gate_role" not in payload
    assert "gate_execution_model" not in payload


def test_report_to_dict_roundtrip_states() -> None:
    d = report_to_dict(_evaluate())
    # reports/2.0 maps the v5 statuses into the five-state vocabulary (ADR-013).
    assert set(d["summary_by_status"].keys()) <= {
        "PASS",
        "FAIL",
        "UNKNOWN",
        "NOT_APPLICABLE",
        "ATTESTED",
        "SELF_ATTESTED",
    }
