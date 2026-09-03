"""A posture flag that is not exactly `true` never earns a pass, and self-attested is not a pass.

The AWS pipeline controls read a JSON file the adopter wrote about their own account. Two rules
keep that honest, and both are asserted here in each direction:

- a required flag must be literally `true`; anything short of that lists the flag by name and
  drops the control to `self-attested`, which is a claim on record, not a verified one;
- `pass` is reserved for evidence the kit collected from the AWS API itself. The same file with
  the same flags is `self-attested` when a human typed it and `pass` when `collect-evidence`
  produced it -- so the test asserts the *collection method*, not just the status.

`aws-level-3` additionally requires the service role, and that difference is asserted against a
non-strict profile so the extra requirement cannot quietly apply everywhere or nowhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import aws
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_LIVE = {"evidence_collection_method": "live", "collected_at": "2026-08-11T00:00:00Z", "source_url": "https://aws"}

_CP_FLAGS = (
    "manual_approval_before_production",
    "artifact_store_encryption_enabled",
    "production_execution_mode_not_parallel",
)
_CB_FLAGS = ("privileged_mode_disabled", "no_plaintext_credentials_in_project_config")


def _ctx(root: Path, profile_id: str = "aws-level-2") -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id=profile_id,
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(root: Path, name: str, payload: dict[str, Any]) -> None:
    path = root / ".oss-policy-kit" / "evidence" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _codepipeline(root: Path, posture: dict[str, Any], *, live: bool = False) -> None:
    payload: dict[str, Any] = {
        "schema_version": "aws-codepipeline/v1",
        "attested_at": "2026-08-11",
        "attested_by": "aws-api-collection" if live else "platform-team",
        "pipeline": "release-pipeline",
        "posture": posture,
    }
    if live:
        payload["collection"] = _LIVE
    _write(root, "aws-codepipeline.json", payload)


def _codebuild(root: Path, posture: dict[str, Any], *, live: bool = False) -> None:
    payload: dict[str, Any] = {
        "schema_version": "aws-codebuild-project/v1",
        "attested_at": "2026-08-11",
        "attested_by": "aws-api-collection" if live else "platform-team",
        "project": "release-build",
        "posture": posture,
    }
    if live:
        payload["collection"] = _LIVE
    _write(root, "aws-codebuild-project.json", payload)


# --------------------------------------------------------------------------- #
# CodePipeline promotion controls
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("disabled", _CP_FLAGS)
def test_a_disabled_promotion_control_is_named_and_costs_the_pass(disabled: str, tmp_path: Path) -> None:
    """An adopter must be able to read which control is missing without opening the JSON."""

    _codepipeline(tmp_path, dict.fromkeys(_CP_FLAGS, True) | {disabled: False})
    outcome = aws.eval_aws_cp_044(_ctx(tmp_path))

    assert outcome.status is ControlStatus.SELF_ATTESTED
    assert disabled in outcome.reason
    assert outcome.evidence_collection_method is EvidenceCollectionMethod.MANUAL


def test_api_collected_evidence_keeps_its_provenance_even_when_the_posture_falls_short(tmp_path: Path) -> None:
    """The verdict drops, but how the evidence was gathered is a separate fact and survives."""

    _codepipeline(tmp_path, dict.fromkeys(_CP_FLAGS, True) | {"manual_approval_before_production": False}, live=True)
    outcome = aws.eval_aws_cp_044(_ctx(tmp_path))

    assert outcome.status is ControlStatus.SELF_ATTESTED
    assert outcome.evidence_collection_method is EvidenceCollectionMethod.LIVE


def test_a_fully_enabled_posture_only_passes_when_the_api_collected_it(tmp_path: Path) -> None:
    _codepipeline(tmp_path, dict.fromkeys(_CP_FLAGS, True))
    assert aws.eval_aws_cp_044(_ctx(tmp_path)).status is ControlStatus.SELF_ATTESTED

    _codepipeline(tmp_path, dict.fromkeys(_CP_FLAGS, True), live=True)
    assert aws.eval_aws_cp_044(_ctx(tmp_path)).status is ControlStatus.PASS


# --------------------------------------------------------------------------- #
# CodeBuild project posture
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("disabled", _CB_FLAGS)
def test_a_disabled_build_posture_flag_is_named_and_costs_the_pass(disabled: str, tmp_path: Path) -> None:
    _codebuild(tmp_path, dict.fromkeys(_CB_FLAGS, True) | {disabled: False})
    outcome = aws.eval_aws_cb_045(_ctx(tmp_path))

    assert outcome.status is ControlStatus.SELF_ATTESTED
    assert disabled in outcome.reason


def test_a_fully_enabled_build_posture_only_passes_when_the_api_collected_it(tmp_path: Path) -> None:
    _codebuild(tmp_path, dict.fromkeys(_CB_FLAGS, True))
    assert aws.eval_aws_cb_045(_ctx(tmp_path)).status is ControlStatus.SELF_ATTESTED

    _codebuild(tmp_path, dict.fromkeys(_CB_FLAGS, True), live=True)
    outcome = aws.eval_aws_cb_045(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert outcome.evidence_collection_method is EvidenceCollectionMethod.LIVE


def test_the_service_role_is_required_only_by_the_strict_profiles(tmp_path: Path) -> None:
    """The extra requirement must apply to `aws-level-3` and to nothing weaker."""

    _codebuild(tmp_path, dict.fromkeys(_CB_FLAGS, True), live=True)

    assert aws.eval_aws_cb_045(_ctx(tmp_path, "aws-level-2")).status is ControlStatus.PASS
    strict = aws.eval_aws_cb_045(_ctx(tmp_path, "aws-level-3"))
    assert strict.status is ControlStatus.SELF_ATTESTED
    assert "codebuild_service_role_configured" in strict.reason


def test_the_strict_profile_passes_once_the_service_role_is_recorded(tmp_path: Path) -> None:
    _codebuild(tmp_path, dict.fromkeys((*_CB_FLAGS, "codebuild_service_role_configured"), True), live=True)
    assert aws.eval_aws_cb_045(_ctx(tmp_path, "aws-level-3")).status is ControlStatus.PASS
