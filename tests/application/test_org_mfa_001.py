"""ORG-MFA-001: graceful degradation when evidence is absent or MFA not enforced."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_org_mfa_001
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_evidence(tmp_path: Path, payload: dict) -> Path:
    evidence_dir = tmp_path / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_file = evidence_dir / "org-mfa-posture.json"
    evidence_file.write_text(json.dumps(payload), encoding="utf-8")
    return evidence_file


def _valid_payload(*, mfa_all: bool, mfa_admins: bool = True) -> dict:
    return {
        "schema_version": "org-mfa-posture/v1",
        "attested_at": "2026-04-19",
        "attested_by": "security-team",
        "org_name": "my-org",
        "platform": "github",
        "mfa_required_for_all_members": mfa_all,
        "mfa_required_for_admins": mfa_admins,
    }


def test_org_mfa_001_self_attested_when_mfa_required_for_all_members(tmp_path: Path) -> None:
    """Evidence with mfa_required_for_all_members: true → SELF_ATTESTED (max achievable via manual evidence).

    The org-mfa schema does not support a collection block so evidence cannot be API-backed.
    SELF_ATTESTED is the correct best-case outcome for this control with manual attestation.
    """
    _write_evidence(tmp_path, _valid_payload(mfa_all=True))
    out = eval_org_mfa_001(_ctx(tmp_path))
    assert out.status == ControlStatus.SELF_ATTESTED


def test_org_mfa_001_fails_when_mfa_not_required_for_members(tmp_path: Path) -> None:
    """Evidence with mfa_required_for_all_members: false → FAIL."""
    _write_evidence(tmp_path, _valid_payload(mfa_all=False, mfa_admins=False))
    out = eval_org_mfa_001(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


def test_org_mfa_001_fails_when_mfa_admins_only(tmp_path: Path) -> None:
    """Evidence with mfa for admins only (not all members) → FAIL."""
    _write_evidence(tmp_path, _valid_payload(mfa_all=False, mfa_admins=True))
    out = eval_org_mfa_001(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "admins only" in out.reason.lower() or "non-admin" in out.reason.lower()


def test_org_mfa_001_manual_review_when_evidence_absent(tmp_path: Path) -> None:
    """No evidence file → MANUAL_REVIEW_REQUIRED with clear message."""
    out = eval_org_mfa_001(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "org" in out.reason.lower() or "mfa" in out.reason.lower()


def test_org_mfa_001_manual_review_when_evidence_has_invalid_schema(tmp_path: Path) -> None:
    """Invalid evidence schema (missing required fields) → MANUAL_REVIEW_REQUIRED."""
    _write_evidence(tmp_path, {"schema_version": "org-mfa-posture/v1", "invalid": "data"})
    out = eval_org_mfa_001(_ctx(tmp_path))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
