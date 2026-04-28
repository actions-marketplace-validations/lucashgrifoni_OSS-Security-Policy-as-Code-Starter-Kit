"""AWS-PIPEIAM-056 and AWS-CBIDENT-057: IAM boundary evaluator scenarios."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_aws_cbident_057, eval_aws_pipeiam_056
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="aws-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_evidence(tmp_path: Path, filename: str, payload: dict) -> None:
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / filename).write_text(json.dumps(payload), encoding="utf-8")


def _codepipeline_payload(*, service_role: bool, method: str = "live") -> dict:
    return {
        "schema_version": "aws-codepipeline/v1",
        "attested_at": "2026-04-19",
        "attested_by": "aws-api-collection",
        "pipeline": "kit-pipeline",
        "posture": {
            "manual_approval_before_production": True,
            "artifact_store_encryption_enabled": True,
            "production_execution_mode_not_parallel": True,
        },
        "collection": {
            "evidence_collection_method": method,
            "collected_at": "2026-04-19T00:00:00Z",
            "source_url": "https://codepipeline.us-east-1.amazonaws.com/pipeline/kit-pipeline",
        },
        "iam": {"pipeline_service_role_arn_configured": service_role},
    }


def _codebuild_payload(*, role_present: bool, no_plaintext: bool, method: str = "live") -> dict:
    return {
        "schema_version": "aws-codebuild-project/v1",
        "attested_at": "2026-04-19",
        "attested_by": "aws-api-collection",
        "project": "kit-build",
        "posture": {
            "privileged_mode_disabled": True,
            "no_plaintext_credentials_in_project_config": True,
            "codebuild_service_role_configured": role_present,
        },
        "collection": {
            "evidence_collection_method": method,
            "collected_at": "2026-04-19T00:00:00Z",
            "source_url": "https://codebuild.us-east-1.amazonaws.com/project/kit-build",
        },
        "identity": {
            "service_role_arn_present": role_present,
            "no_plaintext_environment_credentials": no_plaintext,
        },
    }


# ── AWS-PIPEIAM-056: CodePipeline service role boundary ──────────────────────


def test_aws_pipeiam_056_manual_review_when_no_evidence(tmp_path: Path) -> None:
    """No evidence file → MANUAL_REVIEW_REQUIRED."""
    out = eval_aws_pipeiam_056(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_aws_pipeiam_056_pass_with_live_evidence_and_service_role(tmp_path: Path) -> None:
    """Evidence with pipeline service role + live API collection → PASS."""
    _write_evidence(tmp_path, "aws-codepipeline.json", _codepipeline_payload(service_role=True, method="live"))
    out = eval_aws_pipeiam_056(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_aws_pipeiam_056_self_attested_when_service_role_manually_attested(tmp_path: Path) -> None:
    """Manually attested evidence with service role → SELF_ATTESTED (not PASS)."""
    payload = _codepipeline_payload(service_role=True, method="manual")
    payload["attested_by"] = "security-team"  # non-API attester → not api-backed
    _write_evidence(tmp_path, "aws-codepipeline.json", payload)
    out = eval_aws_pipeiam_056(_ctx(tmp_path))
    assert out.status == ControlStatus.SELF_ATTESTED


def test_aws_pipeiam_056_manual_review_when_iam_fields_absent(tmp_path: Path) -> None:
    """Evidence without iam block → MANUAL_REVIEW_REQUIRED (absence of data ≠ FAIL)."""
    payload = _codepipeline_payload(service_role=True, method="live")
    del payload["iam"]  # simulate AccessDeniedException on IAM call — no iam block in evidence
    _write_evidence(tmp_path, "aws-codepipeline.json", payload)
    out = eval_aws_pipeiam_056(_ctx(tmp_path))
    # Absence of IAM data must not be treated as a FAIL — not enough data to assert
    assert out.status in (ControlStatus.MANUAL_REVIEW_REQUIRED, ControlStatus.SELF_ATTESTED)


# ── AWS-CBIDENT-057: CodeBuild execution identity boundary ───────────────────


def test_aws_cbident_057_manual_review_when_no_evidence(tmp_path: Path) -> None:
    """No evidence file → MANUAL_REVIEW_REQUIRED."""
    out = eval_aws_cbident_057(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_aws_cbident_057_pass_with_live_evidence_and_service_role(tmp_path: Path) -> None:
    """Live evidence with service role + no plaintext credentials → PASS."""
    _write_evidence(tmp_path, "aws-codebuild-project.json", _codebuild_payload(role_present=True, no_plaintext=True))
    out = eval_aws_cbident_057(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_aws_cbident_057_self_attested_when_identity_flags_missing(tmp_path: Path) -> None:
    """Evidence where service_role_arn_present is False → SELF_ATTESTED (not FAIL)."""
    _write_evidence(tmp_path, "aws-codebuild-project.json", _codebuild_payload(role_present=False, no_plaintext=True))
    out = eval_aws_cbident_057(_ctx(tmp_path))
    # service_role_arn_present: False → SELF_ATTESTED (insufficient proof, not hard fail)
    assert out.status == ControlStatus.SELF_ATTESTED


def test_aws_cbident_057_manual_review_when_identity_block_absent(tmp_path: Path) -> None:
    """Evidence without identity block → MANUAL_REVIEW_REQUIRED (data insufficient)."""
    payload = _codebuild_payload(role_present=True, no_plaintext=True)
    del payload["identity"]  # simulate IAM call not made or AccessDeniedException
    _write_evidence(tmp_path, "aws-codebuild-project.json", payload)
    out = eval_aws_cbident_057(_ctx(tmp_path))
    # Absence of identity data must not FAIL — cannot assert credential posture without data
    assert out.status in (ControlStatus.MANUAL_REVIEW_REQUIRED, ControlStatus.SELF_ATTESTED)
