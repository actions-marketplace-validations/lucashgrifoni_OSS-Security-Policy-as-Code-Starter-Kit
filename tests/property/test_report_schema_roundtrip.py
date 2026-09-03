"""Property-based tests for evaluation report schema roundtrip."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
from hypothesis import given, settings
from hypothesis import strategies as st

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PROFILES = ["github-level-1", "github-level-2", "container-baseline-1", "oss-publish-readiness-1"]
SAMPLE_TARGETS = [REPO_ROOT / "examples" / "hardened-repo", REPO_ROOT / "examples" / "vulnerable-repo"]
# v9.0.0 (ADR-043): reports/2.0 is the only contract.
SCHEMA_BY_CONTRACT = {
    "2.0": REPO_ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "reports" / "2.0.json",
}


def _report_payload(profile_id: str, target: Path, contract: str) -> dict[str, Any]:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    report = evaluate_repository(
        repo_root=target,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
        report_json_contract=contract,
    )
    return report_to_dict(report)


@given(
    profile_id=st.sampled_from(SAMPLE_PROFILES),
    target=st.sampled_from(SAMPLE_TARGETS),
    contract=st.just("2.0"),
)
@settings(max_examples=16, deadline=None)
def test_report_validates_against_declared_schema(profile_id: str, target: Path, contract: str) -> None:
    payload = _report_payload(profile_id, target, contract)
    schema = json.loads(SCHEMA_BY_CONTRACT[contract].read_text(encoding="utf-8"))

    jsonschema.validate(payload, schema)
    jsonschema.validate(json.loads(json.dumps(payload)), schema)


@given(contract=st.just("2.0"))
@settings(max_examples=8, deadline=None)
def test_report_contract_keeps_sanitized_target_path(contract: str) -> None:
    payload = _report_payload("github-level-1", REPO_ROOT, contract)
    target_path = payload["target_path"]

    assert "Lucas" not in target_path
    assert "\\" not in target_path
