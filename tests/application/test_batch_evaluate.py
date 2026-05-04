"""Batch evaluation aggregates and gates."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE, ROOT

from oss_policy_kit.application.batch_evaluate import (
    discover_batch_targets,
    is_likely_repository,
    run_batch_evaluation,
)


def test_discover_skips_dot_directories(tmp_path: Path) -> None:
    (tmp_path / "visible").mkdir()
    (tmp_path / ".hidden").mkdir()
    found = discover_batch_targets(tmp_path, include=None, exclude=None)
    assert [p.name for p in found] == ["visible"]


def test_readme_alone_is_not_a_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# just docs", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is False
    assert sig == ""


def test_readme_plus_package_json_is_a_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# app", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "app"}', encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "package.json"


def test_git_dir_is_a_repository(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == ".git"


def test_scripts_dir_with_readme_not_a_repository(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# utility scripts", encoding="utf-8")
    (tmp_path / "helper.py").write_text("print('hello')", encoding="utf-8")
    ok, _sig = is_likely_repository(tmp_path)
    assert ok is False


def test_nested_azure_pipeline_marks_likely_repository(tmp_path: Path) -> None:
    nested = tmp_path / "pipelines" / "azure"
    nested.mkdir(parents=True)
    (nested / "ci.yml").write_text("trigger: [main]\n", encoding="utf-8")
    ok, sig = is_likely_repository(tmp_path)
    assert ok is True
    assert sig == "pipelines/azure/*.yml"


def test_batch_all_tied_true_when_same_fail_counts(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    a = mono / "a"
    b = mono / "b"
    shutil.copytree(EXAMPLE_VULNERABLE, a)
    shutil.copytree(EXAMPLE_VULNERABLE, b)
    out = tmp_path / "out"
    result = run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        fail_on="none",
    )
    assert result.gate_violated is False
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert payload["all_tied"] is True
    assert payload["common_fail_count"] is not None
    md = (out / "evaluation-batch.md").read_text(encoding="utf-8")
    assert "share the same failure count" in md
    assert "failure_distribution" in md or "Failure distribution" in md


def test_batch_not_all_tied_mixed_scores(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_HARDENED, mono / "good")
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "bad")
    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert payload["all_tied"] is False
    assert payload["common_fail_count"] is None


def test_batch_fail_on_gate_violated(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "bad")
    out = tmp_path / "out"
    result = run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        fail_on="fail",
    )
    assert result.gate_violated is True


def test_skip_non_repos_lists_skipped(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    good = mono / "svc"
    good.mkdir(parents=True)
    (good / "README.md").write_text("# svc", encoding="utf-8")
    (good / "pyproject.toml").write_text('[project]\nname = "svc"\nversion = "0.0.0"\n', encoding="utf-8")
    noise = mono / "scripts"
    noise.mkdir()
    out = tmp_path / "out"
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        skip_non_repos=True,
    )
    payload = json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8"))
    skipped = payload.get("skipped_directories") or []
    assert len(skipped) == 1
    assert skipped[0]["name"] == "scripts"
    md = (out / "evaluation-batch.md").read_text(encoding="utf-8")
    assert "Skipped directories" in md


def test_progress_callback_invoked_per_run(tmp_path: Path) -> None:
    mono = tmp_path / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "a")
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "b")
    out = tmp_path / "out"
    cb = MagicMock()
    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1", "github-level-2"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        progress_callback=cb,
    )
    assert cb.call_count == 4


def test_repositories_fixture_batch_smoke(tmp_path: Path) -> None:
    """Existing regression target: fixture folder under tests/fixtures/repositories."""

    root = ROOT / "tests" / "fixtures" / "repositories"
    if not root.is_dir():
        pytest.skip("fixture repositories dir missing")
    out = tmp_path / "batch"
    run_batch_evaluation(
        target_root=root,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )
    assert (out / "evaluation-batch.json").is_file()
