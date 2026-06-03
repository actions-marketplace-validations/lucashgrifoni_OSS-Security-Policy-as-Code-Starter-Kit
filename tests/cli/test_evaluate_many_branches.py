"""In-process branch coverage for the ``evaluate-many`` error and exit-code paths.

The CI smoke for ``evaluate-many`` runs via subprocess (not coverage-instrumented), so
the handler branches in ``cli/batch.py`` were unmeasured. These ``CliRunner`` tests drive
the exit-code contract in-process:

    0  completed; gate not violated (default --fail-on none)
    1  --fail-on fail/degraded and the gate was violated
    2  invalid --profiles / --fail-on / --target-root
    3  unexpected internal error
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.conftest import ROOT
from typer.testing import CliRunner

from oss_policy_kit.cli import batch as bt
from oss_policy_kit.cli.main import app

runner = CliRunner()

_REPOS = ROOT / "tests" / "fixtures" / "repositories"
_EXAMPLES = ROOT / "examples"


def test_empty_profiles_exits_2(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        ["evaluate-many", "--target-root", str(_REPOS), "--profiles", " , ", "--output-dir", str(tmp_path / "o")],
    )
    assert res.exit_code == 2, res.output


def test_bad_fail_on_exits_2(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(_REPOS),
            "--profiles",
            "github-level-1",
            "--fail-on",
            "bogus",
            "--output-dir",
            str(tmp_path / "o"),
        ],
    )
    assert res.exit_code == 2, res.output


def test_bad_target_root_exits_2(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(tmp_path / "nope"),
            "--profiles",
            "github-level-1",
            "--output-dir",
            str(tmp_path / "o"),
        ],
    )
    assert res.exit_code == 2, res.output


def test_quiet_run_exits_0(tmp_path: Path) -> None:
    # --quiet exercises the false side of both `if not quiet:` branches (progress callback
    # and the skipped-directory warning). Default --fail-on none -> exit 0 regardless of statuses.
    out = tmp_path / "o"
    res = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(_REPOS),
            "--profiles",
            "github-level-1",
            "--output-dir",
            str(out),
            "--skip-non-repos",
            "--quiet",
        ],
    )
    assert res.exit_code == 0, res.output
    assert (out / "evaluation-batch.json").is_file()


def test_gate_violated_exits_1(tmp_path: Path) -> None:
    # examples/ contains vulnerable-repo, which fails github-level-1 -> gate violated.
    res = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(_EXAMPLES),
            "--profiles",
            "github-level-1",
            "--fail-on",
            "fail",
            "--output-dir",
            str(tmp_path / "o"),
            "--skip-non-repos",
            "--quiet",
        ],
    )
    assert res.exit_code == 1, res.output


def test_unexpected_error_exits_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(bt, "run_batch_evaluation", _boom)
    res = runner.invoke(
        app,
        [
            "evaluate-many",
            "--target-root",
            str(_REPOS),
            "--profiles",
            "github-level-1",
            "--output-dir",
            str(tmp_path / "o"),
        ],
    )
    assert res.exit_code == 3, res.output
