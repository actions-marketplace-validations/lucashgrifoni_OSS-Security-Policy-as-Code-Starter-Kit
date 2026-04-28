"""Automated checks for documented adoption paths (minimal, recommended, local hardening evidence)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.conftest import AWS_HARDENED_FIXTURE, AWS_MINIMAL_FIXTURE, EXAMPLE_HARDENED

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id

_VALID_BRANCH_EVIDENCE = {
    "schema_version": "branch-protection/v1",
    "attested_at": "2026-04-01",
    "attested_by": "adoption-test",
    "branch": "main",
    "protections": {
        "require_pull_request_reviews": True,
        "dismiss_stale_reviews": True,
        "require_status_checks": True,
        "enforce_admins": True,
        "restrict_force_push": True,
    },
}


def test_recommended_bundle_github_level_1_pass_14() -> None:
    """Recommended copy-paste bundle target: examples/hardened-repo on github-level-1."""

    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    assert report.summary_by_status.get("pass") == 14


def test_minimal_repo_is_not_full_baseline(tmp_path: Path) -> None:
    """Minimal learning tree should not reach the recommended all-pass bar."""

    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")
    report = evaluate_repository(
        repo_root=tmp_path,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    assert report.summary_by_status.get("pass", 0) < 14


def test_hardening_local_release_profile_all_sixteen_pass(tmp_path: Path) -> None:
    """Local hardening with valid branch-protection evidence: all 16 controls pass (PLAT is evidence-backed)."""

    dest = tmp_path / "hardening-local"
    shutil.copytree(EXAMPLE_HARDENED, dest)
    evidence_dir = dest / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "branch-protection.json").write_text(
        json.dumps(_VALID_BRANCH_EVIDENCE),
        encoding="utf-8",
    )

    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-release-hardening-1")
    report = evaluate_repository(
        repo_root=dest,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    assert report.summary_by_status.get("pass") == 16
    assert report.summary_by_status.get("self-attested", 0) == 0


def test_hardened_repo_level2_profile_adds_stricter_non_breaking_signals() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-2")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    statuses = {r.control_id: r.status.value for r in report.results}
    assert statuses["GH-WF-018"] == "pass"
    assert statuses["GH-WF-019"] == "pass"
    assert statuses["GH-WF-020"] == "pass"


def test_hardened_repo_level3_fixture_exercises_extreme_github_evidence() -> None:
    """Hardened example ships synthetic evidence so GH-PLAT-* can reach PASS (still self-attested/manual elsewhere)."""

    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-3")
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    statuses = {r.control_id: r.status.value for r in report.results}
    assert statuses["GH-PLAT-024"] == "pass"
    assert statuses["GH-MERGEQ-053"] == "pass"


def test_aws_minimal_fixture_is_not_level1_full_pass() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "aws-level-1")
    report = evaluate_repository(
        repo_root=AWS_MINIMAL_FIXTURE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    statuses = {r.control_id: r.status.value for r in report.results}
    assert statuses["AWS-CI-037"] == "pass"
    assert statuses["AWS-SECRET-038"] == "manual-review-required"
    assert statuses["AWS-SEC-039"] == "fail"


def test_aws_hardened_fixture_level1_all_aws_controls_pass() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "aws-level-1")
    report = evaluate_repository(
        repo_root=AWS_HARDENED_FIXTURE,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    statuses = {r.control_id: r.status.value for r in report.results}
    for cid in (
        "AWS-CI-037",
        "AWS-SECRET-038",
        "AWS-SEC-039",
        "AWS-SCA-040",
        "AWS-SBOM-041",
    ):
        assert statuses[cid] == "pass"
