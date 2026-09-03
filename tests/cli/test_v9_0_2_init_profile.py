"""Regression tests for the v9.0.2 ``init --profile`` validation hotfix.

Bug (MED): ``init`` silently accepted an unknown ``--profile`` (exit 0) and
wrote a poisoned ``oss-policy-kit.yaml`` that a later ``evaluate`` would reject.

Fix: when ``--profile`` is user-supplied, ``init`` validates it against the
bundled profile set using the same lookup ``evaluate`` uses
(``resolve_profile_file`` over ``data/profiles/<id>/profile.yaml``) BEFORE any
filesystem write (including under ``--dry-run``). An unknown id raises
``InvalidInputError`` -> exit 2 and writes nothing. Valid bundled ids and the
removed ``cra-eu-ready-2-1`` alias is rejected with a pointer; external YAML paths stay
valid.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.application.init_planner import CONFIG_FILENAME
from oss_policy_kit.cli.main import app, prepare_cli_args


def _make_empty_repo(tmp_path: Path, name: str = "repo") -> Path:
    """Create an empty directory so init runs with no platform signals."""

    repo = tmp_path / name
    repo.mkdir()
    return repo


def test_init_unknown_profile_exits_2_and_writes_nothing(tmp_path: Path) -> None:
    repo = _make_empty_repo(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(["init", "--target", str(repo), "--profile", "mars-level-99"]),
    )

    assert result.exit_code == 2, result.output
    assert "mars-level-99" in result.output
    assert "profiles" in result.output.lower()
    # The poisoned config must never reach the filesystem.
    assert not (repo / CONFIG_FILENAME).exists()


def test_init_unknown_profile_dry_run_also_blocks(tmp_path: Path) -> None:
    # Even --dry-run must reject the bad id (build_init_plan runs in both paths).
    repo = _make_empty_repo(tmp_path, name="dry-repo")
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(["init", "--target", str(repo), "--profile", "mars-level-99", "--dry-run"]),
    )

    assert result.exit_code == 2, result.output
    assert not (repo / CONFIG_FILENAME).exists()


def test_init_valid_bundled_profile_still_succeeds(tmp_path: Path) -> None:
    repo = _make_empty_repo(tmp_path, name="ok-repo")
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(["init", "--target", str(repo), "--profile", "github-level-2"]),
    )

    assert result.exit_code == 0, result.output
    cfg = repo / CONFIG_FILENAME
    assert cfg.is_file()
    assert "github-level-2" in cfg.read_text(encoding="utf-8")


def test_init_removed_alias_profile_exits_2_with_pointer(tmp_path: Path) -> None:
    # v10.0.0: the cra-eu-ready-2-1 alias was removed (ADR-029 one-major cycle done);
    # init must reject it BEFORE writing config, pointing at the canonical id.
    repo = _make_empty_repo(tmp_path, name="alias-repo")
    runner = CliRunner()

    result = runner.invoke(
        app,
        prepare_cli_args(["init", "--target", str(repo), "--profile", "cra-eu-ready-2-1"]),
    )

    assert result.exit_code == 2, result.output
    assert "cra-eu-conformance-evidence-1" in result.output
    assert not (repo / CONFIG_FILENAME).is_file()
