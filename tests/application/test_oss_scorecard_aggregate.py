"""OSS-SCORECARD-001: aggregate-score preference and proxy fallback.

These tests pin the maturity contract of `eval_oss_scorecard_001` after it was
hardened to prefer the official OpenSSF Scorecard aggregate `score`:

- When the Scorecard JSON exposes the root ``score`` field, the evaluator must
  use it with ``confidence="high"`` and no proxy warning.
- When only per-check scores are present, the evaluator falls back to the
  arithmetic mean as a proxy with ``confidence="low"`` and a clear operational
  warning explaining that Scorecard itself uses a weighted aggregate.
- When neither the aggregate nor usable per-check scores are present, the
  evaluator reports ``MANUAL_REVIEW_REQUIRED`` instead of inventing a pass.
"""

from __future__ import annotations

import json
from pathlib import Path

from oss_policy_kit.adapters.scorecard_json import load_scorecard_json
from oss_policy_kit.application.evaluators import EvalContext, eval_oss_scorecard_001
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(repo: Path, bundle) -> EvalContext:  # type: ignore[no-untyped-def]
    return EvalContext(
        repo_root=repo,
        profile_id="github-release-hardening-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=bundle,
    )


def _write_scorecard(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_official_aggregate_pass_has_high_confidence(tmp_path: Path) -> None:
    """An official aggregate >= threshold must PASS with high confidence."""
    p = tmp_path / "sc.json"
    _write_scorecard(
        p,
        {
            "scorecard": {
                "version": "1",
                "score": 7.5,
                "checks": [{"name": "Pinned-Dependencies", "score": 9}],
            }
        },
    )
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score == 7.5
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"
    assert "official `score` field" in out.reason
    assert not out.operational_warnings


def test_official_aggregate_below_threshold_fails_with_high_confidence(tmp_path: Path) -> None:
    """An official aggregate below threshold must FAIL with high confidence."""
    p = tmp_path / "sc.json"
    _write_scorecard(
        p,
        {
            "scorecard": {
                "version": "1",
                "score": 3.2,
                "checks": [{"name": "Pinned-Dependencies", "score": 4}],
            }
        },
    )
    bundle = load_scorecard_json(p)
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.FAIL
    assert out.confidence == "high"
    assert "official `score` field" in out.reason
    assert not out.operational_warnings


def test_root_level_aggregate_is_captured(tmp_path: Path) -> None:
    """Top-level ``score`` (not nested under ``scorecard``) must also be used."""
    p = tmp_path / "sc.json"
    _write_scorecard(
        p,
        {
            "score": 8.1,
            "checks": [{"name": "Token-Permissions", "score": 10}],
        },
    )
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score == 8.1
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "high"


def test_proxy_fallback_when_no_aggregate_low_confidence_and_warns(tmp_path: Path) -> None:
    """Without aggregate, arithmetic mean is a proxy with low confidence + warning."""
    p = tmp_path / "sc.json"
    _write_scorecard(
        p,
        {
            "scorecard": {
                "version": "1",
                "checks": [
                    {"name": "Pinned-Dependencies", "score": 9},
                    {"name": "Token-Permissions", "score": 9},
                    {"name": "Security-Policy", "score": 3},
                ],
            }
        },
    )
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score is None
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "low"
    assert out.operational_warnings
    joined = " ".join(out.operational_warnings)
    assert "weighted aggregate" in joined
    assert "proxy" in out.reason.lower()


def test_proxy_fallback_below_threshold_fails_low_confidence(tmp_path: Path) -> None:
    """Proxy score below threshold must FAIL and keep the proxy warning."""
    p = tmp_path / "sc.json"
    _write_scorecard(
        p,
        {
            "scorecard": {
                "checks": [
                    {"name": "Pinned-Dependencies", "score": 1},
                    {"name": "Token-Permissions", "score": 2},
                ],
            }
        },
    )
    bundle = load_scorecard_json(p)
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.FAIL
    assert out.confidence == "low"
    assert out.operational_warnings


def test_manual_review_when_neither_aggregate_nor_check_scores(tmp_path: Path) -> None:
    """No usable data anywhere must result in MANUAL_REVIEW_REQUIRED."""
    p = tmp_path / "sc.json"
    _write_scorecard(p, {"scorecard": {"version": "1", "checks": []}})
    bundle = load_scorecard_json(p)
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert out.confidence == "low"


def test_manual_review_when_only_boolean_per_check_scores(tmp_path: Path) -> None:
    """Boolean per-check scores are invalid and must not produce a proxy score."""
    p = tmp_path / "sc.json"
    _write_scorecard(
        p,
        {
            "scorecard": {
                "version": "1",
                "checks": [
                    {"name": "Pinned-Dependencies", "score": True},
                    {"name": "Token-Permissions", "score": False},
                ],
            }
        },
    )
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score is None
    assert all(c.score is None for c in bundle.checks)
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
    assert out.confidence == "low"
    assert "proxy score" not in out.reason.lower()


def test_out_of_range_aggregate_is_ignored_and_falls_back_to_proxy(tmp_path: Path) -> None:
    """Invalid aggregate (>10 or <0) must be discarded; proxy path must engage."""
    p = tmp_path / "sc.json"
    _write_scorecard(
        p,
        {
            "scorecard": {
                "score": 42,
                "checks": [
                    {"name": "Pinned-Dependencies", "score": 8},
                    {"name": "Security-Policy", "score": 6},
                ],
            }
        },
    )
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score is None
    out = eval_oss_scorecard_001(_ctx(tmp_path, bundle))
    assert out.status == ControlStatus.PASS
    assert out.confidence == "low"
    assert out.operational_warnings


def test_not_evaluated_when_no_scorecard_bundle(tmp_path: Path) -> None:
    """No Scorecard provided must remain NOT_EVALUATED (no silent pass)."""
    out = eval_oss_scorecard_001(_ctx(tmp_path, None))
    assert out.status == ControlStatus.NOT_EVALUATED
    assert out.confidence == "low"
