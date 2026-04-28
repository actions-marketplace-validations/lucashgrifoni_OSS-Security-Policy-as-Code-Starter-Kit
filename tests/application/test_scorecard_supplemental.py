"""Scorecard supplemental explainability on SEC-CODEQL-010 and report fields."""

from __future__ import annotations

from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE, ROOT

from oss_policy_kit.adapters.scorecard_json import load_scorecard_json
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.domain.models import ControlStatus

FIXTURE_SCORECARD = ROOT / "tests" / "fixtures" / "scorecard.sample.json"


def test_scorecard_influences_codeql_when_workflows_lack_signal() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    bundle = load_scorecard_json(FIXTURE_SCORECARD)
    report = evaluate_repository(
        repo_root=EXAMPLE_VULNERABLE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=bundle,
    )
    codeql = next(r for r in report.results if r.control_id == "SEC-CODEQL-010")
    assert codeql.status == ControlStatus.PASS
    assert report.scorecard_supplemental is not None
    assert report.scorecard_supplemental["check_count"] >= 1
    assert "SEC-CODEQL-010" in report.scorecard_supplemental["influenced_control_ids"]


def test_scorecard_supplemental_notes_no_influence_when_workflows_satisfy_codeql() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    bundle = load_scorecard_json(FIXTURE_SCORECARD)
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=bundle,
    )
    assert report.scorecard_supplemental is not None
    assert report.scorecard_supplemental["workflows_satisfied_codeql_signal"] is True
    assert report.scorecard_supplemental["influenced_control_ids"] == []
