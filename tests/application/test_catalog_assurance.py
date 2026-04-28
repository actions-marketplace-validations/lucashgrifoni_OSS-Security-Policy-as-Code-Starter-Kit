"""Catalog assurance field (introduced v3.0.1; catalog coverage tests ship with v3.1.0)."""

from __future__ import annotations

from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict

_ALLOWED = frozenset({"deterministic", "signal", "evidence-backed"})


def test_catalog_loads_assurance_for_all_controls() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    for cid, spec in catalog.items():
        assert cid == spec.id
        assert spec.assurance in _ALLOWED, cid


def test_new_controls_have_expected_assurance() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    assert catalog["GH-MERGEQ-053"].assurance == "signal"
    assert catalog["GH-WF-019"].assurance == "deterministic"
    assert catalog["GH-WF-020"].assurance == "deterministic"
    assert catalog["GOV-EVIDFRESH-054"].assurance == "deterministic"
    assert catalog["CI-WFCALLSHA-055"].assurance == "deterministic"
    assert catalog["AWS-PIPE-042"].assurance == "deterministic"
    assert catalog["AWS-SECRET-038"].assurance == "deterministic"
    assert catalog["AWS-PIPEIAM-056"].assurance == "evidence-backed"
    assert catalog["AWS-SBOMART-058"].assurance == "evidence-backed"
    assert catalog["AZ-PIPE-027"].assurance == "deterministic"
    assert catalog["GH-WF-018"].assurance == "deterministic"
    assert catalog["AZ-PIPE-028"].assurance == "deterministic"
    assert catalog["AZ-PIPE-029"].assurance == "deterministic"
    assert catalog["AZ-PIPE-030"].assurance == "deterministic"
    assert catalog["AZ-SEC-031"].assurance == "signal"
    assert catalog["AZ-PLAT-034"].assurance == "evidence-backed"
    assert catalog["AZ-PLAT-035"].assurance == "evidence-backed"
    assert catalog["AZ-IDENT-036"].assurance == "evidence-backed"
    assert catalog["AZ-SCONN-056"].assurance == "evidence-backed"
    assert catalog["AZ-WIFEV-057"].assurance == "evidence-backed"
    assert catalog["AZ-ARTSBOM-058"].assurance == "evidence-backed"
    assert catalog["AZ-ARTPRV-059"].assurance == "evidence-backed"
    assert catalog["PLAT-BRPROT-015"].assurance == "evidence-backed"


def test_report_json_v03_includes_assurance_per_result() -> None:
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
    payload = report_to_dict(report)
    assert "reports/0.3" in payload["schema_version"]
    for row in payload["results"]:
        assert row["assurance"] in _ALLOWED
        assert row["control_id"] in catalog
        assert row["assurance"] == catalog[row["control_id"]].assurance
