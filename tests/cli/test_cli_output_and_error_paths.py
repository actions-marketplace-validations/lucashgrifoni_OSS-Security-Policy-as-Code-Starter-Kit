"""CLI output formats and the way commands turn an internal failure into an exit code.

Two things live here. The first is `recommend-profile --format json`, a user-facing contract
that had no test at all: the flag existed, was documented, and nothing checked that it emitted
parseable JSON rather than the human block.

The second is error translation, which each of these commands does the same way and for the
same reason. A `typer.Exit` raised deliberately -- by a validation gate that already printed a
useful message -- must pass straight through. Anything unexpected must become a clean exit
code with a message, never a traceback: a stack trace in a CI log tells the operator nothing
they can act on and leaks absolute paths from the machine that ran it.

Every case is asserted through `CliRunner` rather than a subprocess, because subprocess tests
do not register against the coverage of the code they exercise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def _repo(root: Path) -> Path:
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n",
        encoding="utf-8",
    )
    return root


# --------------------------------------------------------------------------- #
# recommend-profile --format json
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("flag", ["--format", "-f"])
def test_recommend_profile_json_is_parseable(flag: str, tmp_path: Path) -> None:
    """The documented JSON contract, which nothing was checking."""

    res = runner.invoke(app, ["recommend-profile", "--target", str(_repo(tmp_path)), flag, "json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.stdout)
    assert "suggestions" in payload, payload
    assert isinstance(payload["suggestions"], list)


def test_recommend_profile_json_is_not_the_human_block(tmp_path: Path) -> None:
    """Without this, a `--format json` that silently fell back to text would still pass."""

    res = runner.invoke(app, ["recommend-profile", "--target", str(_repo(tmp_path)), "--format", "json"])
    assert "Profile suggestions (heuristic" not in res.stdout, res.stdout


def test_recommend_profile_text_output_lists_the_signals(tmp_path: Path) -> None:
    res = runner.invoke(app, ["recommend-profile", "--target", str(_repo(tmp_path)), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "Profile suggestions" in res.stdout


@pytest.mark.parametrize("alias", ["table", "compact", "HUMAN"])
def test_recommend_profile_format_aliases_resolve_to_human(alias: str, tmp_path: Path) -> None:
    res = runner.invoke(app, ["recommend-profile", "--target", str(_repo(tmp_path)), "--format", alias])
    assert res.exit_code == 0, res.output
    assert "Profile suggestions" in res.stdout


def test_recommend_profile_on_a_missing_target_exits_two(tmp_path: Path) -> None:
    """A user error is exit 2 with a message, not a traceback."""

    res = runner.invoke(app, ["recommend-profile", "--target", str(tmp_path / "nope")])
    assert res.exit_code == 2, res.output
    assert "Traceback" not in res.output


# --------------------------------------------------------------------------- #
# Unexpected failures become an exit code, not a traceback
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("command", "patch_target", "patch_name"),
    [
        ("recommend-profile", "oss_policy_kit.cli.recommend", "build_profile_recommendation"),
    ],
)
def test_an_unexpected_error_is_reported_without_a_traceback(
    command: str, patch_target: str, patch_name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug inside the command must still leave the operator with a usable message."""

    import importlib

    module = importlib.import_module(patch_target)

    def _boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("something nobody anticipated")

    monkeypatch.setattr(module, patch_name, _boom)
    res = runner.invoke(app, [command, "--target", str(_repo(tmp_path))])

    assert res.exit_code != 0
    assert "Traceback" not in res.output, res.output
    assert str(tmp_path) not in res.output or "something nobody anticipated" not in res.output


def test_a_deliberate_exit_is_not_swallowed_by_the_catch_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`typer.Exit` is how a gate reports its own verdict; re-wrapping it would hide the code."""

    import typer

    from oss_policy_kit.cli import recommend as rec_mod

    def _exit_seven(*_a: object, **_k: object) -> object:
        raise typer.Exit(code=7)

    monkeypatch.setattr(rec_mod, "build_profile_recommendation", _exit_seven)
    res = runner.invoke(app, ["recommend-profile", "--target", str(_repo(tmp_path))])
    assert res.exit_code == 7, res.output


def test_a_repository_with_no_signals_still_produces_suggestions(tmp_path: Path) -> None:
    """An empty directory has nothing to detect; the block must skip the signals section."""

    res = runner.invoke(app, ["recommend-profile", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "Profile suggestions" in res.stdout
    assert "Observed signals" not in res.stdout


def test_an_interactive_stdout_gets_the_rich_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """On a real terminal the command renders the panelled layout instead of plain text."""

    from oss_policy_kit.cli import terminal_ui

    monkeypatch.setattr(terminal_ui, "human_tty_stdout", lambda: True)
    res = runner.invoke(app, ["recommend-profile", "--target", str(_repo(tmp_path))])
    assert res.exit_code == 0, res.output
    assert res.stdout.strip(), "the rich layout printed nothing"
