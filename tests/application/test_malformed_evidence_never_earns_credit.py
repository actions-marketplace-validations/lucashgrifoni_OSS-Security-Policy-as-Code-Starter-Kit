"""Evidence that parses as JSON but does not match its schema.

Distinct from the scaffold case in ``test_scaffolded_evidence_never_earns_credit.py``: there
the file is well-formed and honestly unfilled, here it is the wrong shape entirely -- an
outdated collector, a hand-edited file, a payload from a different tool. The invariant is the
same and is asserted first for every control: malformed evidence never earns credit.

**Every platform answers `manual-review-required`, and that is the rule ADR-045 settled.** A
schema violation is a fact about the file, not about the repository: the kit did not find the
control unsatisfied, it failed to read the document that would say. Reporting `fail` would have
the gate assert something it never established -- the mirror of the `SAST-SEMGREP-064` defect,
where unreadable evidence was reported as `pass`.

Until 2026-08-12 the five GitHub ruleset/environment/secret-scanning controls plus
`PLAT-BRPROT-015` answered `fail` here while Azure and AWS answered `manual-review-required`,
and the split was accidental -- `_parse_branch_protection_evidence` even disagreed with itself,
answering `manual-review-required` for unreadable JSON and a non-object root but `fail` for a
schema violation three branches later.

`_EXPECTED` still names the status per control rather than asserting one constant, so a future
divergence shows up as a diff on the row that moved instead of a silent flip.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import aws, azure, github, governance
from oss_policy_kit.application.evaluators._shared import EvalContext, EvalOutcome
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

Evaluator = Callable[[EvalContext], EvalOutcome]

_MRR = ControlStatus.MANUAL_REVIEW_REQUIRED

#: platform -> (profile, [(evaluator, status it returns for malformed evidence)])
_EXPECTED: dict[str, tuple[str, list[tuple[Evaluator, ControlStatus]]]] = {
    "azure": (
        "azure-level-2",
        [
            (azure.eval_az_plat_034, _MRR),
            (azure.eval_az_plat_035, _MRR),
            (azure.eval_az_sconn_056, _MRR),
            (azure.eval_az_wifev_057, _MRR),
            (azure.eval_az_artsbom_058, _MRR),
            (azure.eval_az_artprv_059, _MRR),
        ],
    ),
    "github": (
        "github-level-2",
        [
            (github.eval_gh_plat_024, _MRR),
            (github.eval_gh_immutrel_070, _MRR),
            (github.eval_org_actpol_071, _MRR),
            (github.eval_gh_plat_025, _MRR),
            (github.eval_gh_plat_026, _MRR),
            (governance.eval_plat_brprot_015, _MRR),
            (governance.eval_org_mfa_001, _MRR),
        ],
    ),
    "aws": (
        "aws-level-2",
        [
            (aws.eval_aws_cp_044, _MRR),
            (aws.eval_aws_cb_045, _MRR),
            (aws.eval_aws_cbident_057, _MRR),
            (aws.eval_aws_sbomart_058, _MRR),
            (aws.eval_aws_provart_059, _MRR),
        ],
    ),
}

_CREDIT = {ControlStatus.PASS, ControlStatus.SELF_ATTESTED, ControlStatus.ATTESTED}


def _malformed_evidence(root: Path, platform: str) -> EvalContext:
    """Scaffold the platform's evidence, then replace every file with the wrong shape."""

    scaffold_evidence_files(root, platform)
    for path in (root / ".oss-policy-kit" / "evidence").glob("*.json"):
        path.write_text(json.dumps({"unexpected": True}), encoding="utf-8")
    profile_id, _ = _EXPECTED[platform]
    return EvalContext(
        repo_root=root,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


@pytest.mark.parametrize("platform", sorted(_EXPECTED))
def test_malformed_evidence_never_earns_a_control_any_credit(platform: str, tmp_path: Path) -> None:
    """The invariant that holds everywhere, whatever the refusal is called."""

    ctx = _malformed_evidence(tmp_path, platform)
    for evaluate, _ in _EXPECTED[platform][1]:
        outcome = evaluate(ctx)
        assert outcome.status not in _CREDIT, f"{evaluate.__name__} credited malformed {platform} evidence"


@pytest.mark.parametrize("platform", sorted(_EXPECTED))
def test_the_refusal_says_the_evidence_did_not_match_its_schema(platform: str, tmp_path: Path) -> None:
    """Naming the schema is what makes this fixable; 'invalid evidence' would not be."""

    ctx = _malformed_evidence(tmp_path, platform)
    for evaluate, _ in _EXPECTED[platform][1]:
        outcome = evaluate(ctx)
        assert "schema" in (outcome.reason or "").lower(), f"{evaluate.__name__}: {outcome.reason}"


@pytest.mark.parametrize("platform", sorted(_EXPECTED))
def test_the_current_per_platform_verdict_is_pinned(platform: str, tmp_path: Path) -> None:
    """Pins the per-control verdict, so a divergence shows up as a diff on the row that moved."""

    ctx = _malformed_evidence(tmp_path, platform)
    actual = {evaluate.__name__: evaluate(ctx).status for evaluate, _ in _EXPECTED[platform][1]}
    expected = {evaluate.__name__: status for evaluate, status in _EXPECTED[platform][1]}
    assert actual == expected


def test_valid_evidence_is_not_refused_for_a_schema_problem(tmp_path: Path) -> None:
    """The counterpart: without it, a validator that rejected everything would pass above."""

    scaffold_evidence_files(tmp_path, "azure")
    ctx = EvalContext(
        repo_root=tmp_path,
        profile_id="azure-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )
    outcome: Any = azure.eval_az_plat_034(ctx)
    assert "schema" not in (outcome.reason or "").lower(), outcome.reason
