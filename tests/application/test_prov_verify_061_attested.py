"""ADR-028 PR3: PROV-VERIFY-061 emits ATTESTED (opt-in) on a verified attestation record.

A fully verified provenance record (transparency-log inclusion + fresh verified_at)
is the canonical ATTESTED case. It is gated behind ``--enable-attested`` (default off →
historical PASS), and the emission is fail-closed: any verification gap keeps the prior
FAIL / MANUAL_REVIEW_REQUIRED outcome and never becomes ATTESTED.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.evaluators import EvalContext, eval_prov_verify_061
from oss_policy_kit.application.loader import ProfileSpec, bundled_kit_root, load_catalog
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_CATALOG = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
_FRESH_TS = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ctx(tmp_path: Path, *, enable_attested: bool) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        enable_attested=enable_attested,
    )


def _gh_payload(*, verified_at: str = _FRESH_TS, transparency: bool = True, omit_verification: bool = False) -> dict:
    payload: dict = {
        "schema_version": "github-provenance-artifact/v1",
        "attested_at": "2026-04-21",
        "attested_by": "release-bot",
        "artifact": {
            "uri": "https://github.com/example-org/example-repo/releases/download/v1/example.tgz",
            "digest_sha256": "e7c2a4d8f1b6c9d2e5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6f9a2b5c8d1e4",
        },
        "attestation": {
            "kind": "github-artifact-attestation",
            "digest_sha256": "b3a6c9d2e5f8a1b4c7d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6",
        },
        "posture": {
            "attestation_covers_release_artifact": True,
            "attestation_digest_recorded": True,
            "artifact_digest_recorded": True,
        },
    }
    if not omit_verification:
        payload["verification"] = {
            "method": "gh-attestation-verify",
            "verified_at": verified_at,
            "transparency_log_inclusion": transparency,
            "issuer": "https://token.actions.githubusercontent.com",
            "tool_version": "gh 2.62.0",
        }
    return payload


def _write_evidence(tmp_path: Path, payload: dict) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "github-provenance-artifact.json").write_text(json.dumps(payload), encoding="utf-8")


# --------------------------------------------------------------------------- #
# evaluator: PASS (default) vs ATTESTED (opt-in)
# --------------------------------------------------------------------------- #


def test_verified_attestation_is_pass_by_default(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _gh_payload())
    out = eval_prov_verify_061(_ctx(tmp_path, enable_attested=False))
    assert out.status == ControlStatus.PASS


def test_verified_attestation_is_attested_when_enabled(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _gh_payload())
    out = eval_prov_verify_061(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.ATTESTED
    assert "verified" in out.reason.lower()
    # honesty: the remediation/basis states the kit validated a record, did not re-verify
    assert "did not" in out.remediation.lower()


# --------------------------------------------------------------------------- #
# fail-closed: a verification gap is never laundered into ATTESTED
# --------------------------------------------------------------------------- #


def test_no_transparency_log_stays_fail_even_with_attested(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _gh_payload(transparency=False))
    out = eval_prov_verify_061(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.FAIL


def test_stale_verification_stays_fail_even_with_attested(tmp_path: Path) -> None:
    stale = (datetime.now(UTC) - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write_evidence(tmp_path, _gh_payload(verified_at=stale))
    out = eval_prov_verify_061(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.FAIL


def test_missing_verification_block_stays_manual_review_even_with_attested(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _gh_payload(omit_verification=True))
    out = eval_prov_verify_061(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


def test_no_evidence_stays_manual_review_even_with_attested(tmp_path: Path) -> None:
    out = eval_prov_verify_061(_ctx(tmp_path, enable_attested=True))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# engine integration: the report carries ATTESTED only with the flag
# --------------------------------------------------------------------------- #


def _prov_status(tmp_path: Path, *, enable_attested: bool) -> ControlStatus:
    profile = ProfileSpec(id="t", title="t", description="d", audience="a", control_ids=("PROV-VERIFY-061",))
    report = evaluate_repository(
        repo_root=tmp_path,
        profile=profile,
        catalog=_CATALOG,
        waiver_outcome=None,
        scorecard=None,
        enable_attested=enable_attested,
    )
    return report.results[0].status


def test_engine_report_attested_only_with_flag(tmp_path: Path) -> None:
    _write_evidence(tmp_path, _gh_payload())
    assert _prov_status(tmp_path, enable_attested=False) == ControlStatus.PASS
    assert _prov_status(tmp_path, enable_attested=True) == ControlStatus.ATTESTED
