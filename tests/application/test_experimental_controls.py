"""Tests for experimental SEC-* controls on github-level-2."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import load_catalog, load_profile_by_id, merge_kit_root

_MINIMAL_WORKFLOW_YAML = "on: push\njobs: {x: {runs-on: ubuntu-latest, steps: [{run: echo}]}}\n"


def _eval_l2(repo: Path) -> dict[str, str]:
    root = merge_kit_root(None)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-2")
    report = evaluate_repository(repo, profile, catalog, waiver_outcome=None, scorecard=None)
    return {r.control_id: r.status.value for r in report.results}


def test_sec_secrets_050_passes_on_gitleaks_keyword(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "sec.yml").write_text(
        "on: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: gitleaks/gitleaks-action@v2\n",
        encoding="utf-8",
    )
    statuses = _eval_l2(tmp_path)
    assert statuses.get("SEC-SECRETS-050") == "pass"


def test_sec_gitignore_051_fails_without_gitignore(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(_MINIMAL_WORKFLOW_YAML, encoding="utf-8")
    statuses = _eval_l2(tmp_path)
    assert statuses.get("SEC-GITIGNORE-051") == "fail"


def test_sec_pinlock_052_fails_node_without_lockfile(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"x"}', encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(_MINIMAL_WORKFLOW_YAML, encoding="utf-8")
    statuses = _eval_l2(tmp_path)
    assert statuses.get("SEC-PINLOCK-052") == "fail"
