"""Branch protection evidence: JSON Schema alignment and evaluator behavior."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import ROOT

from oss_policy_kit.application.evaluators import (
    EvalContext,
    _parse_branch_protection_evidence,
    eval_plat_brprot_015,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

SCHEMA_REPORTS = ROOT / "reports" / "schema" / "evidence-branch-protection.schema.json"
SCHEMA_PACKAGED = ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "evidence-branch-protection.schema.json"


def test_packaged_branch_protection_schema_matches_public_copy() -> None:
    """Avoid drift between the published schema path and the wheel-shipped copy."""

    assert SCHEMA_REPORTS.read_text(encoding="utf-8") == SCHEMA_PACKAGED.read_text(encoding="utf-8")


def test_invalid_branch_protection_schema_surfaces_validation_message(tmp_path: Path) -> None:
    p = tmp_path / "branch-protection.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "wrong",
                "attested_at": "not-a-date",
                "branch": "main",
            }
        ),
        encoding="utf-8",
    )
    out = _parse_branch_protection_evidence(p)
    assert out.status == ControlStatus.FAIL
    assert "evidence-branch-protection.schema.json" in out.reason


def test_valid_branch_protection_all_enabled_is_pass(tmp_path: Path) -> None:
    p = tmp_path / "branch-protection.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "branch-protection/v1",
                "attested_at": "2026-04-01",
                "attested_by": "test-user",
                "branch": "main",
                "protections": {
                    "require_pull_request_reviews": True,
                    "dismiss_stale_reviews": True,
                    "require_status_checks": True,
                    "enforce_admins": True,
                    "restrict_force_push": True,
                },
            }
        ),
        encoding="utf-8",
    )
    out = _parse_branch_protection_evidence(p)
    assert out.status == ControlStatus.PASS
    assert "required protections attested" in out.reason.lower()


def test_valid_branch_protection_live_collection_marks_live_method(tmp_path: Path) -> None:
    p = tmp_path / "branch-protection.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "branch-protection/v1",
                "attested_at": "2026-04-01",
                "attested_by": "github-api-collection",
                "branch": "main",
                "protections": {
                    "require_pull_request_reviews": True,
                    "dismiss_stale_reviews": True,
                    "require_status_checks": True,
                    "enforce_admins": True,
                    "restrict_force_push": True,
                },
                "collection": {
                    "evidence_collection_method": "live",
                    "collected_at": "2026-04-01T10:00:00Z",
                    "source_url": "https://api.github.com/repos/org/repo/branches/main/protection",
                    "mode": "api",
                },
            }
        ),
        encoding="utf-8",
    )
    out = _parse_branch_protection_evidence(p)
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method.value == "live"


def test_plat_brprot_015_without_evidence_file_is_not_evaluated(tmp_path: Path) -> None:
    ctx = EvalContext(
        repo_root=tmp_path,
        profile_id="github-release-hardening-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )
    out = eval_plat_brprot_015(ctx)
    assert out.status == ControlStatus.NOT_EVALUATED
    assert "branch protection" in out.reason.lower()
    # v3 maturity uplift (P1-B): reason must cite the exact expected evidence path
    # and remediation must direct users to the platform collector command.
    assert ".oss-policy-kit/evidence/branch-protection.json" in out.reason
    assert "collect-evidence" in out.remediation.lower()


def test_branch_protection_false_flag_is_self_attested_with_gap_list(tmp_path: Path) -> None:
    p = tmp_path / "branch-protection.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "branch-protection/v1",
                "attested_at": "2026-04-01",
                "attested_by": "test-user",
                "branch": "main",
                "protections": {
                    "require_pull_request_reviews": True,
                    "dismiss_stale_reviews": False,
                    "require_status_checks": True,
                    "enforce_admins": True,
                    "restrict_force_push": True,
                },
            }
        ),
        encoding="utf-8",
    )
    out = _parse_branch_protection_evidence(p)
    assert out.status == ControlStatus.FAIL
    assert "dismiss_stale_reviews" in out.reason
