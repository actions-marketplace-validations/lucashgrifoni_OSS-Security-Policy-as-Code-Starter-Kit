"""Regression tests for validation findings (GOV-DISC-013, SEC-CODEQL-010, batch, waivers)."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED, ROOT

from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.evaluators import EvalContext, eval_gov_disc_013, eval_sec_codeql_010
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id
from oss_policy_kit.application.reporting import report_to_dict
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis, analyze_workflows

ADVISORY_REPO = ROOT / "tests" / "fixtures" / "repositories" / "github-advisory-disclosure"
SEMGBAND_REPO = ROOT / "tests" / "fixtures" / "repositories" / "github-semgrep-bandit-sast"


def test_gov_disc_passes_with_explicit_private_github_reporting() -> None:
    """Fixture ties GitHub Security Advisories to explicit private reporting language."""

    out = eval_gov_disc_013(
        EvalContext(
            repo_root=ADVISORY_REPO,
            profile_id="github-level-1",
            workflows=WorkflowAnalysis(),
            azure_pipelines=AzurePipelineAnalysis(),
            aws_ci=AwsCiAnalysis(),
            scorecard=None,
        )
    )
    assert out.status == ControlStatus.PASS


def test_gov_disc_generic_github_security_advisories_only_is_manual(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text(
        "# Security\n\nThis project uses GitHub Security Advisories for release coordination.\n",
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
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_sec_codeql_passes_on_semgrep_and_bandit_workflows() -> None:
    wf = analyze_workflows(SEMGBAND_REPO)
    assert "semgrep" in wf.sast_ci_signals
    assert "bandit" in wf.sast_ci_signals
    out = eval_sec_codeql_010(
        EvalContext(
            repo_root=SEMGBAND_REPO,
            profile_id="github-level-1",
            workflows=wf,
            azure_pipelines=AzurePipelineAnalysis(),
            aws_ci=AwsCiAnalysis(),
            scorecard=None,
        )
    )
    assert out.status == ControlStatus.PASS
    assert "semgrep" in out.reason
    assert "bandit" in out.reason


def test_gov_disc_manual_when_security_without_channel(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "SECURITY.md").write_text("# Security\nWe care about security.\n", encoding="utf-8")
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
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_external_waiver_path_serialized_in_report(tmp_path: Path) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    waiver_path = ROOT / "tests" / "fixtures" / "waivers.ci-danger.yaml"
    w = parse_waivers_file(waiver_path)
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=w,
        scorecard=None,
        external_waiver_path=str(waiver_path.resolve()),
    )
    payload = report_to_dict(report)
    # Privacy-by-default (v9.0.2): the report sanitizes the external-waiver path to its basename
    # unless --include-absolute-path is set, exactly like target_path. The field stays serialized.
    assert payload["external_waiver_path"] == waiver_path.name


def test_batch_evaluate_runs_multiple_children(tmp_path: Path) -> None:
    root = tmp_path / "mono"
    a = root / "repo a"
    b = root / "repo-b"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    (a / "SECURITY.md").write_text("Contact: security@example.com\n", encoding="utf-8")
    (b / "SECURITY.md").write_text("Contact: security@example.com\n", encoding="utf-8")
    outd = tmp_path / "batch-out"
    run_batch_evaluation(
        target_root=root,
        profile_ids=["github-level-1"],
        output_dir=outd,
        kit_root=None,
        include=None,
        exclude=None,
    )
    batch = json.loads((outd / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert len(batch["runs"]) == 2
    names = {run["target_name"] for run in batch["runs"]}
    assert names == {"repo a", "repo-b"}
    md = (outd / "evaluation-batch.md").read_text(encoding="utf-8")
    assert "`repo a`" in md or "repo a" in md
    assert "Consolidated status totals" in md
    assert (outd / "evaluation-batch.md").is_file()
