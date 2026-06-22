"""CLI-level regression tests for the v9.0.1 fast-follow fixes.

- M1/M2: a blank ``--report-json-contract`` value exits 2 (fail-closed), not 0.
- L5: a mistyped subcommand exits 2 with a "No such command" error instead of being
  routed to ``evaluate`` as a target path (the confusing "Not a directory" message).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()


def _make_github_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    return repo


@pytest.mark.parametrize("blank", ["", "   "])
def test_cli_blank_report_contract_exits_2(tmp_path: Path, blank: str) -> None:
    repo = _make_github_repo(tmp_path)
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "evaluate",
                "--target",
                str(repo),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(tmp_path / "out"),
                "--report-json-contract",
                blank,
            ]
        ),
    )
    assert result.exit_code == 2, result.output


def test_cli_unknown_subcommand_is_not_routed_to_evaluate() -> None:
    # `recommend` is a typo of `recommend-profile`; it must surface as an unknown
    # command, never as a "Not a directory" target-path error.
    result = runner.invoke(app, prepare_cli_args(["recommend"]))
    assert result.exit_code == 2
    combined = (result.output or "") + (str(result.exception) if result.exception else "")
    assert "Not a directory" not in combined


def test_cli_known_subcommand_still_dispatches() -> None:
    # The compat shim must keep routing real subcommands untouched.
    assert prepare_cli_args(["recommend-profile", "--target", "."])[0] == "recommend-profile"
    result = runner.invoke(app, ["profiles"])
    assert result.exit_code == 0, result.output
