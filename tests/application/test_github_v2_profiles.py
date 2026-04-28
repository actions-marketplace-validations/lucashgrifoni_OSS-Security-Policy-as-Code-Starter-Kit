"""Profile and evidence coverage for GitHub v2/v3 controls."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED, ROOT

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


def test_hardened_repo_level2_and_level3_expected_shape() -> None:
    level2 = _evaluate(EXAMPLE_HARDENED, "github-level-2")
    statuses2 = {r.control_id: r.status.value for r in level2.results}
    assert statuses2["GH-WF-018"] == "pass"
    assert statuses2["GH-WF-019"] == "pass"
    assert statuses2["GH-WF-020"] == "pass"
    assert statuses2["GH-REL-021"] == "pass"

    level3 = _evaluate(EXAMPLE_HARDENED, "github-level-3")
    statuses3 = {r.control_id: r.status.value for r in level3.results}
    assert statuses3["GH-MERGEQ-053"] == "pass"
    assert statuses3["GH-PLAT-024"] == "pass"
    assert statuses3["GOV-EVIDFRESH-054"] == "pass"


def test_release_hardening_3_accepts_valid_platform_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(EXAMPLE_HARDENED, repo)
    evidence_dir = repo / ".oss-policy-kit" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    (evidence_dir / "branch-protection.json").write_text(
        json.dumps(
            {
                "schema_version": "branch-protection/v1",
                "attested_at": "2026-04-01",
                "attested_by": "qa",
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

    (evidence_dir / "github-rulesets.json").write_text(
        json.dumps(
            {
                "schema_version": "github-rulesets/v1",
                "attested_at": "2026-04-01",
                "attested_by": "qa",
                "repository": "org/repo",
                "posture": {
                    "require_pull_request": True,
                    "require_status_checks": True,
                    "restrict_force_push": True,
                    "require_code_owner_review": True,
                },
            }
        ),
        encoding="utf-8",
    )

    (evidence_dir / "github-environment-protection.json").write_text(
        json.dumps(
            {
                "schema_version": "github-environment-protection/v1",
                "attested_at": "2026-04-01",
                "attested_by": "qa",
                "environments": [
                    {
                        "name": "production",
                        "requires_reviewers": True,
                        "prevent_self_review": True,
                        "wait_timer_minutes": 5,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    (evidence_dir / "github-secret-scanning.json").write_text(
        json.dumps(
            {
                "schema_version": "github-secret-scanning/v1",
                "attested_at": "2026-04-01",
                "attested_by": "qa",
                "repository": "org/repo",
                "posture": {
                    "secret_scanning_enabled": True,
                    "push_protection_enabled": True,
                    "validity_checks_enabled": True,
                },
            }
        ),
        encoding="utf-8",
    )

    report = _evaluate(repo, "github-release-hardening-3")
    status = {r.control_id: r.status.value for r in report.results}
    assert status["GOV-EVIDFRESH-054"] == "pass"
    assert status["PLAT-BRPROT-015"] == "pass"
    assert status["GH-PLAT-024"] == "pass"
    assert status["GH-PLAT-025"] == "pass"
    assert status["GH-PLAT-026"] == "pass"


def test_schema_copies_match_reports_schema() -> None:
    names = [
        "evidence-github-rulesets.schema.json",
        "evidence-github-environment-protection.schema.json",
        "evidence-github-secret-scanning.schema.json",
    ]
    for name in names:
        reports = (ROOT / "reports" / "schema" / name).read_text(encoding="utf-8")
        packaged = (ROOT / "src" / "oss_policy_kit" / "data" / "schema" / name).read_text(encoding="utf-8")
        assert reports == packaged
