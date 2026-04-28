"""Azure profile coverage and evidence behavior."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.conftest import AZURE_HARDENED_FIXTURE, AZURE_MINIMAL_FIXTURE, ROOT

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id


def _evaluate(repo: Path, profile_id: str):
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, profile_id)
    return evaluate_repository(
        repo_root=repo,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )


def test_azure_minimal_has_pipeline_presence_but_missing_hardening_signals() -> None:
    report = _evaluate(AZURE_MINIMAL_FIXTURE, "azure-level-1")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["AZ-PIPE-027"] == "pass"
    assert status["AZ-PIPE-028"] == "fail"
    assert status["AZ-SEC-031"] == "fail"


def test_azure_hardened_level_2_detects_stricter_pipeline_signals() -> None:
    report = _evaluate(AZURE_HARDENED_FIXTURE, "azure-level-2")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["AZ-PIPE-027"] == "pass"
    assert status["AZ-PIPE-028"] == "pass"
    assert status["AZ-PIPE-029"] == "pass"
    assert status["AZ-PIPE-030"] == "pass"
    # v3 maturity uplift: YAML-only signal without evidence is no longer sufficient for PASS.
    # AZ-IDENT-036 now requires azure-pipeline-governance.json or returns MANUAL_REVIEW_REQUIRED.
    assert status["AZ-IDENT-036"] == "manual-review-required"


def test_azure_release_hardening_with_evidence_is_self_attested(tmp_path: Path) -> None:
    repo = tmp_path / "azure-release"
    shutil.copytree(AZURE_HARDENED_FIXTURE, repo)
    evidence_dir = repo / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "azure-branch-policies.json").write_text(
        json.dumps(
            {
                "schema_version": "azure-branch-policies/v1",
                "attested_at": "2026-04-15",
                "attested_by": "qa",
                "project": "proj",
                "repository": "repo",
                "branch": "main",
                "posture": {
                    "minimum_reviewers_enabled": True,
                    "build_validation_enabled": True,
                    "comment_resolution_required": True,
                    "reset_votes_on_push": True,
                    "block_last_pusher_approval": True,
                    "bypass_policy_restricted": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "azure-pipeline-governance.json").write_text(
        json.dumps(
            {
                "schema_version": "azure-pipeline-governance/v1",
                "attested_at": "2026-04-15",
                "attested_by": "qa",
                "project": "proj",
                "posture": {
                    "approvals_required": True,
                    "environment_checks_enabled": True,
                    "service_connection_restricted": True,
                    "federated_identity_preferred": True,
                },
                "service_connections": [
                    {
                        "name": "prod-wif",
                        "authentication": "workload_identity_federation",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    # `azure-release-hardening-1` adds platform evidence on top of the starter set only; rh-3 also
    # requires GOV-EVIDFRESH, artifact SBOM/provenance, and decomposed service-connection gates.
    report = _evaluate(repo, "azure-release-hardening-1")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["AZ-PLAT-034"] == "self-attested"
    assert status["AZ-PLAT-035"] == "self-attested"


def test_azure_level_3_flags_missing_artifact_evidence(tmp_path: Path) -> None:
    """Hard-gate profile requires artifact-bound SBOM/provenance JSON, not only governance files."""

    repo = tmp_path / "azure-l3"
    shutil.copytree(AZURE_HARDENED_FIXTURE, repo)
    (repo / "CODEOWNERS").write_text("* @example/maintainers\n", encoding="utf-8")
    evidence_dir = repo / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "azure-branch-policies.json").write_text(
        json.dumps(
            {
                "schema_version": "azure-branch-policies/v1",
                "attested_at": "2026-04-17",
                "attested_by": "qa",
                "project": "proj",
                "repository": "repo",
                "branch": "main",
                "posture": {
                    "minimum_reviewers_enabled": True,
                    "build_validation_enabled": True,
                    "comment_resolution_required": True,
                    "reset_votes_on_push": True,
                    "block_last_pusher_approval": True,
                    "bypass_policy_restricted": True,
                },
            }
        ),
        encoding="utf-8",
    )
    (evidence_dir / "azure-pipeline-governance.json").write_text(
        json.dumps(
            {
                "schema_version": "azure-pipeline-governance/v1",
                "attested_at": "2026-04-17",
                "attested_by": "qa",
                "project": "proj",
                "posture": {
                    "approvals_required": True,
                    "environment_checks_enabled": True,
                    "service_connection_restricted": True,
                    "federated_identity_preferred": True,
                },
                "service_connections": [
                    {
                        "name": "prod-wif",
                        "authentication": "workload_identity_federation",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = _evaluate(repo, "azure-level-3")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["AZ-ARTSBOM-058"] == "manual-review-required"
    assert status["AZ-ARTPRV-059"] == "manual-review-required"


def test_azure_schema_copies_match_reports_schema() -> None:
    names = (
        "evidence-azure-branch-policies.schema.json",
        "evidence-azure-pipeline-governance.schema.json",
        "evidence-azure-sbom-artifact.schema.json",
        "evidence-azure-provenance-artifact.schema.json",
    )
    for name in names:
        public_text = (ROOT / "reports" / "schema" / name).read_text(encoding="utf-8")
        packaged_text = (ROOT / "src" / "oss_policy_kit" / "data" / "schema" / name).read_text(encoding="utf-8")
        assert public_text == packaged_text
