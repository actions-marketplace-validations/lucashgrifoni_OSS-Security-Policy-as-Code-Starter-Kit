"""ADR-038: GH-IMMUTREL-070 (immutable releases) + ORG-ACTPOL-071 (org Actions policy).

Both controls are evidence-backed: absent -> manual review (NOT_EVALUATED), present+valid
-> PASS/FAIL on posture, unfilled scaffold (placeholder) -> manual review, malformed -> FAIL.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators import github as gh
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(tmp_path: Path, *, enable_attested: bool = False) -> gh.EvalContext:
    return gh.EvalContext(
        repo_root=tmp_path,
        profile_id="github-release-hardening-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        enable_attested=enable_attested,
    )


def _fresh_verification(*, transparency: bool = True) -> dict:
    return {
        "method": "gh-attestation-verify",
        "verified_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "transparency_log_inclusion": transparency,
    }


def _ev(tmp_path: Path, name: str, payload: dict) -> None:
    d = tmp_path / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def _immutrel_ev(posture: dict) -> dict:
    return {
        "schema_version": "github-release-immutability/v1",
        "attested_at": "2026-06-01",
        "attested_by": "platform team",
        "repository": "o/r",
        "posture": posture,
    }


def _actpol_ev(posture: dict) -> dict:
    return {
        "schema_version": "github-actions-policy/v1",
        "attested_at": "2026-06-01",
        "attested_by": "platform team",
        "organization": "my-org",
        "posture": posture,
    }


# --------------------------------------------------------------------------- #
# GH-IMMUTREL-070
# --------------------------------------------------------------------------- #


def test_immutrel_absent_is_not_evaluated(tmp_path: Path) -> None:
    assert gh.eval_gh_immutrel_070(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_immutrel_pass(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "github-release-immutability.json",
        _immutrel_ev({"immutable_releases_enabled": True, "release_attestation_present": True}),
    )
    assert gh.eval_gh_immutrel_070(_ctx(tmp_path)).status == ControlStatus.PASS


def test_immutrel_pass_attestation_only(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "github-release-immutability.json",
        _immutrel_ev({"immutable_releases_enabled": False, "release_attestation_present": True}),
    )
    assert gh.eval_gh_immutrel_070(_ctx(tmp_path)).status == ControlStatus.PASS


def test_immutrel_fail_both_off(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "github-release-immutability.json",
        _immutrel_ev({"immutable_releases_enabled": False, "release_attestation_present": False}),
    )
    assert gh.eval_gh_immutrel_070(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_immutrel_malformed_is_fail(tmp_path: Path) -> None:
    _ev(tmp_path, "github-release-immutability.json", {"schema_version": "wrong", "posture": {}})
    assert gh.eval_gh_immutrel_070(_ctx(tmp_path)).status == ControlStatus.FAIL


# --------------------------------------------------------------------------- #
# GH-IMMUTREL-070 ATTESTED upgrade (ADR-028, opt-in, fail-closed)
# --------------------------------------------------------------------------- #


def _immutrel_attested_ev(verification: dict) -> dict:
    payload = _immutrel_ev({"immutable_releases_enabled": True, "release_attestation_present": True})
    payload["verification"] = verification
    return payload


def test_immutrel_attested_when_enabled_and_verified(tmp_path: Path) -> None:
    _ev(tmp_path, "github-release-immutability.json", _immutrel_attested_ev(_fresh_verification()))
    out = gh.eval_gh_immutrel_070(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.ATTESTED


def test_immutrel_pass_not_attested_when_flag_off(tmp_path: Path) -> None:
    # Valid verification present, but --enable-attested is off -> stays PASS (default behavior).
    _ev(tmp_path, "github-release-immutability.json", _immutrel_attested_ev(_fresh_verification()))
    out = gh.eval_gh_immutrel_070(_ctx(tmp_path, enable_attested=False))
    assert out.status == ControlStatus.PASS


def test_immutrel_failclosed_without_verification(tmp_path: Path) -> None:
    # enable_attested on, but no verification record -> fail-closed to PASS, never ATTESTED.
    _ev(
        tmp_path,
        "github-release-immutability.json",
        _immutrel_ev({"immutable_releases_enabled": True, "release_attestation_present": True}),
    )
    out = gh.eval_gh_immutrel_070(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.PASS


def test_immutrel_failclosed_without_transparency(tmp_path: Path) -> None:
    # Verification present but transparency_log_inclusion=false -> fail-closed to PASS.
    _ev(
        tmp_path,
        "github-release-immutability.json",
        _immutrel_attested_ev(_fresh_verification(transparency=False)),
    )
    out = gh.eval_gh_immutrel_070(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.PASS


# --------------------------------------------------------------------------- #
# ORG-ACTPOL-071
# --------------------------------------------------------------------------- #


def test_actpol_absent_is_not_evaluated(tmp_path: Path) -> None:
    assert gh.eval_org_actpol_071(_ctx(tmp_path)).status == ControlStatus.NOT_EVALUATED


def test_actpol_pass(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "github-actions-policy.json",
        _actpol_ev({"allowed_actions": "selected", "sha_pinning_required": True}),
    )
    assert gh.eval_org_actpol_071(_ctx(tmp_path)).status == ControlStatus.PASS


def test_actpol_fail_allowed_all(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "github-actions-policy.json",
        _actpol_ev({"allowed_actions": "all", "sha_pinning_required": True}),
    )
    assert gh.eval_org_actpol_071(_ctx(tmp_path)).status == ControlStatus.FAIL


def test_actpol_fail_no_sha_pin(tmp_path: Path) -> None:
    _ev(
        tmp_path,
        "github-actions-policy.json",
        _actpol_ev({"allowed_actions": "selected", "sha_pinning_required": False}),
    )
    assert gh.eval_org_actpol_071(_ctx(tmp_path)).status == ControlStatus.FAIL


# --------------------------------------------------------------------------- #
# Scaffold template = placeholder -> manual review (not a false PASS/FAIL)
# --------------------------------------------------------------------------- #


def test_scaffold_templates_are_placeholders_pending_review(tmp_path: Path) -> None:
    scaffold_evidence_files(tmp_path, "github")
    ctx = _ctx(tmp_path)
    assert gh.eval_gh_immutrel_070(ctx).status == ControlStatus.NOT_EVALUATED
    assert gh.eval_org_actpol_071(ctx).status == ControlStatus.NOT_EVALUATED


# --------------------------------------------------------------------------- #
# Catalog + registry wiring
# --------------------------------------------------------------------------- #


def test_controls_are_registered_and_evidence_backed() -> None:
    assert "GH-IMMUTREL-070" in EVALUATOR_REGISTRY
    assert "ORG-ACTPOL-071" in EVALUATOR_REGISTRY
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert catalog["GH-IMMUTREL-070"].assurance == "evidence-backed"
    assert catalog["ORG-ACTPOL-071"].assurance == "evidence-backed"
