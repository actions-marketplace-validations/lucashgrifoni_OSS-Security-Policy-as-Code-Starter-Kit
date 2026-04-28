"""GH-PLAT-024/025/026 and GOV-EVIDFRESH-054 evidence behaviour."""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.application.evaluators import (
    EvalContext,
    eval_gh_plat_024,
    eval_gh_plat_025,
    eval_gh_plat_026,
    eval_gov_evidfresh_054,
)
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(repo: Path) -> EvalContext:
    return EvalContext(
        repo_root=repo,
        profile_id="github-release-hardening-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _rulesets_base(**posture: bool) -> dict:
    return {
        "schema_version": "github-rulesets/v1",
        "attested_at": "2026-04-10",
        "attested_by": "test",
        "repository": "org/repo",
        "posture": {
            "require_pull_request": posture.get("require_pull_request", True),
            "require_status_checks": posture.get("require_status_checks", True),
            "restrict_force_push": posture.get("restrict_force_push", True),
            "require_code_owner_review": posture.get("require_code_owner_review", True),
        },
    }


def test_gh_plat_024_not_evaluated_without_file(tmp_path: Path) -> None:
    out = eval_gh_plat_024(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_EVALUATED
    assert "github-rulesets.json" in out.reason


def test_gh_plat_024_fail_on_schema_violation(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "github-rulesets.json").write_text(json.dumps({"schema_version": "wrong"}), encoding="utf-8")
    out = eval_gh_plat_024(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "schema" in out.reason.lower()


def test_gh_plat_024_pass_when_posture_complete(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "github-rulesets.json").write_text(json.dumps(_rulesets_base()), encoding="utf-8")
    out = eval_gh_plat_024(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gh_plat_024_live_collection_marks_live_method(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    payload = _rulesets_base()
    payload["attested_by"] = "github-api-collection"
    payload["collection"] = {
        "evidence_collection_method": "live",
        "collected_at": "2026-04-10T12:00:00Z",
        "source_url": "https://api.github.com/repos/org/repo/rulesets",
        "mode": "api",
    }
    (ev / "github-rulesets.json").write_text(json.dumps(payload), encoding="utf-8")
    out = eval_gh_plat_024(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method.value == "live"


def test_gh_plat_024_fail_when_required_posture_disabled(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    data = _rulesets_base(require_code_owner_review=False)
    (ev / "github-rulesets.json").write_text(json.dumps(data), encoding="utf-8")
    out = eval_gh_plat_024(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "require_code_owner_review" in out.reason


def test_gh_plat_024_placeholder_repository_not_evaluated(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    data = _rulesets_base()
    data["repository"] = "YOUR_ORG/repo"
    (ev / "github-rulesets.json").write_text(json.dumps(data), encoding="utf-8")
    out = eval_gh_plat_024(_ctx(tmp_path))
    assert out.status == ControlStatus.NOT_EVALUATED
    assert "placeholder" in out.reason.lower()


def test_gov_evidfresh_fail_when_github_rulesets_stale(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    stale = _rulesets_base()
    stale["attested_at"] = "2019-01-01"
    (ev / "github-rulesets.json").write_text(json.dumps(stale), encoding="utf-8")
    out = eval_gov_evidfresh_054(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "stale" in out.reason.lower()


def test_gh_plat_025_pass_strict_environment(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    payload = {
        "schema_version": "github-environment-protection/v1",
        "attested_at": "2026-04-10",
        "attested_by": "test",
        "environments": [
            {
                "name": "production",
                "requires_reviewers": True,
                "prevent_self_review": True,
                "wait_timer_minutes": 5,
            }
        ],
    }
    (ev / "github-environment-protection.json").write_text(json.dumps(payload), encoding="utf-8")
    out = eval_gh_plat_025(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gh_plat_025_live_collection_marks_live_method(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    payload = {
        "schema_version": "github-environment-protection/v1",
        "attested_at": "2026-04-10",
        "attested_by": "github-api-collection",
        "environments": [
            {
                "name": "production",
                "requires_reviewers": True,
                "prevent_self_review": True,
                "wait_timer_minutes": 5,
            }
        ],
        "collection": {
            "evidence_collection_method": "live",
            "collected_at": "2026-04-10T12:00:00Z",
            "source_url": "https://api.github.com/repos/org/repo/environments",
            "mode": "api",
        },
    }
    (ev / "github-environment-protection.json").write_text(json.dumps(payload), encoding="utf-8")
    out = eval_gh_plat_025(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method.value == "live"


def test_gh_plat_025_fail_weak_environment(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    payload = {
        "schema_version": "github-environment-protection/v1",
        "attested_at": "2026-04-10",
        "attested_by": "test",
        "environments": [
            {
                "name": "production",
                "requires_reviewers": True,
                "prevent_self_review": True,
                "wait_timer_minutes": 0,
            }
        ],
    }
    (ev / "github-environment-protection.json").write_text(json.dumps(payload), encoding="utf-8")
    out = eval_gh_plat_025(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


def test_gh_plat_026_pass_secret_scanning(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    payload = {
        "schema_version": "github-secret-scanning/v1",
        "attested_at": "2026-04-10",
        "attested_by": "test",
        "repository": "org/repo",
        "posture": {
            "secret_scanning_enabled": True,
            "push_protection_enabled": True,
            "validity_checks_enabled": True,
        },
    }
    (ev / "github-secret-scanning.json").write_text(json.dumps(payload), encoding="utf-8")
    out = eval_gh_plat_026(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gh_plat_026_live_collection_marks_live_method(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    payload = {
        "schema_version": "github-secret-scanning/v1",
        "attested_at": "2026-04-10",
        "attested_by": "github-api-collection",
        "repository": "org/repo",
        "posture": {
            "secret_scanning_enabled": True,
            "push_protection_enabled": True,
            "validity_checks_enabled": True,
        },
        "collection": {
            "evidence_collection_method": "live",
            "collected_at": "2026-04-10T12:00:00Z",
            "source_url": "https://api.github.com/repos/org/repo",
            "mode": "api",
        },
    }
    (ev / "github-secret-scanning.json").write_text(json.dumps(payload), encoding="utf-8")
    out = eval_gh_plat_026(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
    assert out.evidence_collection_method.value == "live"


def test_gh_plat_026_fail_disabled_push_protection(tmp_path: Path) -> None:
    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    payload = {
        "schema_version": "github-secret-scanning/v1",
        "attested_at": "2026-04-10",
        "attested_by": "test",
        "repository": "org/repo",
        "posture": {
            "secret_scanning_enabled": True,
            "push_protection_enabled": False,
            "validity_checks_enabled": True,
        },
    }
    (ev / "github-secret-scanning.json").write_text(json.dumps(payload), encoding="utf-8")
    out = eval_gh_plat_026(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "push_protection_enabled" in out.reason
