"""Evaluation engine integration."""

from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE, ROOT

from oss_policy_kit.adapters.scorecard_json import load_scorecard_json
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.evaluators import EvalContext, eval_gov_disc_013
from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def test_hardened_github_level_1_mostly_passes() -> None:
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
    statuses = {r.control_id: r.status for r in report.results}
    assert statuses["GOV-SEC-001"] == ControlStatus.PASS
    assert statuses["CI-PIN-008"] == ControlStatus.PASS
    assert statuses["SEC-CODEQL-010"] == ControlStatus.PASS


def test_vulnerable_has_expected_failures() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_VULNERABLE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    statuses = {r.control_id: r.status for r in report.results}
    assert statuses["GOV-SEC-001"] == ControlStatus.FAIL
    assert statuses["CI-DANGER-007"] == ControlStatus.FAIL
    assert statuses["CI-PIN-008"] == ControlStatus.FAIL


def test_waiver_mitigates_failure() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    waiver_path = ROOT / "tests" / "fixtures" / "waivers.ci-danger.yaml"
    w = parse_waivers_file(waiver_path)
    report = evaluate_repository(
        repo_root=EXAMPLE_VULNERABLE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=w,
        scorecard=None,
    )
    st = next(r for r in report.results if r.control_id == "CI-DANGER-007")
    assert st.status == ControlStatus.WAIVED
    assert st.waiver is not None


def test_scorecard_supplements_codeql_when_workflow_missing() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    sc_path = ROOT / "tests" / "fixtures" / "scorecard.sample.json"
    bundle = load_scorecard_json(sc_path)
    # Vulnerable workflows lack CodeQL; Scorecard export supplies supplemental signal.
    report = evaluate_repository(
        repo_root=EXAMPLE_VULNERABLE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=bundle,
    )
    st = next(r for r in report.results if r.control_id == "SEC-CODEQL-010")
    assert st.status == ControlStatus.PASS
    assert report.scorecard_path


def test_placeholder_security_contact_fails_disclosure_control(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text(
        """
# Security

Please email the maintainer privately (update this file with a working contact before publishing your fork publicly).
""",
        encoding="utf-8",
    )
    out = eval_gov_disc_013(
        EvalContext(
            repo_root=repo,
            profile_id="github-level-1",
            workflows=WorkflowAnalysis(),
            azure_pipelines=AzurePipelineAnalysis(),
            aws_ci=AwsCiAnalysis(),
            scorecard=None,
        )
    )
    assert out.status == ControlStatus.FAIL


def test_private_vulnerability_reporting_counts_as_private_channel(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text(
        """
# Security

Use GitHub private vulnerability reporting for undisclosed issues.
""",
        encoding="utf-8",
    )
    out = eval_gov_disc_013(
        EvalContext(
            repo_root=repo,
            profile_id="github-level-1",
            workflows=WorkflowAnalysis(),
            azure_pipelines=AzurePipelineAnalysis(),
            aws_ci=AwsCiAnalysis(),
            scorecard=None,
        )
    )
    assert out.status == ControlStatus.PASS


def test_azure_parse_errors_surface_in_operational_warnings(tmp_path: Path) -> None:
    """Malformed azure-pipelines.yml must produce an operational warning (parity with GitHub/AWS)."""

    (tmp_path / "azure-pipelines.yml").write_text(
        "steps: [ unclosed\n",
        encoding="utf-8",
    )
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=tmp_path,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    assert any(w.startswith("Azure pipeline parse issue") for w in report.operational_warnings)


def test_hard_gate_profile_without_evidence_emits_specific_warning(tmp_path: Path) -> None:
    """L3 and release-hardening-3 profiles must cite their id + doc link when evidence is missing."""

    (tmp_path / "README.md").write_text("# empty\n", encoding="utf-8")
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-3")
    report = evaluate_repository(
        repo_root=tmp_path,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    hardgate_hits = [
        w for w in report.operational_warnings if "github-level-3" in w and "release-hardening-workflow.md" in w
    ]
    assert hardgate_hits, "expected a hard-gate evidence warning mentioning profile id and doc link"


def test_level_1_profile_does_not_emit_hard_gate_evidence_warning(tmp_path: Path) -> None:
    """The profile-specific hard-gate evidence warning must not fire on starter profiles."""

    (tmp_path / "README.md").write_text("# empty\n", encoding="utf-8")
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=tmp_path,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    assert not any("release-hardening-workflow.md" in w for w in report.operational_warnings), (
        "L1 profiles must never emit the hard-gate evidence warning"
    )


def test_hard_gate_profile_with_real_evidence_skips_evidence_warning() -> None:
    """When real (non-placeholder) evidence is present, the hard-gate doc link warning is suppressed."""

    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-3")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    assert not any("release-hardening-workflow.md" in w for w in report.operational_warnings), (
        "hardened-repo ships real evidence; the doc-link warning should not fire"
    )
