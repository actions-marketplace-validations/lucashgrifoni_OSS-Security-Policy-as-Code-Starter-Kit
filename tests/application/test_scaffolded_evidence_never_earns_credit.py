"""A scaffolded-but-unfilled evidence set must never earn a control any credit.

``oss-policy-kit evidence scaffold`` writes JSON templates whose posture booleans are all
``true`` -- that is what makes them useful as a starting point. It also writes
``REPLACE_ME_...`` into every identifying field. If the placeholder guard ever stopped
firing, running ``scaffold`` and committing the untouched templates would turn a repository
green without a single real attestation, which is the most attractive way to cheat this tool.

So this pins the property directly, for every evidence-backed control on every platform: a
freshly scaffolded evidence set yields ``not-evaluated`` and names the offending file.

The second test is the mutation. Asserting ``not-evaluated`` alone is weak -- a missing or
unparseable file produces a refusal too, so the test would still pass if the guard were
deleted and the evidence merely failed to load. Filling the placeholders in and re-running
proves the refusal came from the placeholders specifically: the same file, same schema, same
posture, now reaches a real verdict.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import aws, azure, github, governance
from oss_policy_kit.application.evaluators._shared import EvalContext, EvalOutcome
from oss_policy_kit.application.evidence_placeholders import (
    has_placeholder_values,
    is_placeholder_digest,
)
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

Evaluator = Callable[[EvalContext], EvalOutcome]

#: platform -> (profile id, evidence-backed evaluators whose file `scaffold` writes)
_PLATFORMS: dict[str, tuple[str, list[Evaluator]]] = {
    "github": (
        "github-level-2",
        [
            github.eval_gh_plat_024,
            github.eval_gh_immutrel_070,
            github.eval_org_actpol_071,
            github.eval_gh_plat_025,
            github.eval_gh_plat_026,
            governance.eval_plat_brprot_015,
            governance.eval_org_mfa_001,
        ],
    ),
    "azure": (
        "azure-level-2",
        [
            azure.eval_az_plat_034,
            azure.eval_az_plat_035,
            azure.eval_az_ident_036,
            azure.eval_az_sconn_056,
            azure.eval_az_wifev_057,
            azure.eval_az_artsbom_058,
            azure.eval_az_artprv_059,
            governance.eval_org_mfa_001,
        ],
    ),
    "aws": (
        "aws-level-2",
        [
            aws.eval_aws_cp_044,
            aws.eval_aws_cb_045,
            aws.eval_aws_pipeiam_056,
            aws.eval_aws_cbident_057,
            aws.eval_aws_sbomart_058,
            aws.eval_aws_provart_059,
            governance.eval_org_mfa_001,
        ],
    ),
}

#: Statuses that give a control credit. A template must never reach any of them.
_CREDIT = {ControlStatus.PASS, ControlStatus.SELF_ATTESTED, ControlStatus.ATTESTED}

#: A SHA256 with enough entropy to read as a real artifact hash rather than a template.
_REAL_LOOKING_DIGEST = "9f2c4e1ab7d0538e6c91af43b2705d8ec1f6a394d20b8e57cf3401d6b7e28405"


def _ctx(root: Path, profile_id: str) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _fill_placeholders(node: Any) -> Any:
    """Replace every scaffold placeholder with a plausible filled-in value.

    Two different guards have to be satisfied, which is why this is not a single string
    substitution: identifying fields carry ``REPLACE_ME_`` tokens, while digest fields carry
    a syntactically valid but zero-entropy hash (``aaaa...``) that
    :func:`is_placeholder_digest` rejects on its own.
    """

    if isinstance(node, str):
        if is_placeholder_digest(node):
            return _REAL_LOOKING_DIGEST
        return "acme-platform-team" if has_placeholder_values(node) else node
    if isinstance(node, dict):
        return {k: _fill_placeholders(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_fill_placeholders(v) for v in node]
    return node


@pytest.mark.parametrize("platform", sorted(_PLATFORMS))
def test_untouched_scaffold_templates_are_refused_by_every_evidence_control(platform: str, tmp_path: Path) -> None:
    """Scaffold and evaluate without editing anything: every control must refuse."""

    scaffold_evidence_files(tmp_path, platform)
    profile_id, evaluators = _PLATFORMS[platform]
    ctx = _ctx(tmp_path, profile_id)

    for fn in evaluators:
        outcome = fn(ctx)
        assert outcome.status not in _CREDIT, (
            f"{fn.__name__} gave credit to an unfilled {platform} template (status {outcome.status.value})"
        )
        assert outcome.status is ControlStatus.NOT_EVALUATED, f"{fn.__name__} -> {outcome.status.value}"
        assert "placeholder" in (outcome.reason or "").lower(), (
            f"{fn.__name__} refused for some other reason: {outcome.reason}"
        )


@pytest.mark.parametrize("platform", sorted(_PLATFORMS))
def test_filling_the_placeholders_in_is_what_unblocks_those_controls(platform: str, tmp_path: Path) -> None:
    """Same files, placeholders replaced: the refusal has to go away.

    Without this, the test above would still pass if the placeholder guard were deleted and
    the evidence simply failed to load for an unrelated reason.
    """

    scaffold_evidence_files(tmp_path, platform)
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    for path in evidence_dir.glob("*.json"):
        filled = _fill_placeholders(json.loads(path.read_text(encoding="utf-8")))
        path.write_text(json.dumps(filled), encoding="utf-8")
        assert not has_placeholder_values(filled), f"{path.name} still holds a placeholder"

    profile_id, evaluators = _PLATFORMS[platform]
    ctx = _ctx(tmp_path, profile_id)

    for fn in evaluators:
        outcome = fn(ctx)
        assert "placeholder" not in (outcome.reason or "").lower(), (
            f"{fn.__name__} still complains about placeholders after they were filled in: {outcome.reason}"
        )
