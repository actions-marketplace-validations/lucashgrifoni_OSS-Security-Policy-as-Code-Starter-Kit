"""Naming two repositories must not quietly audit one of them.

`evaluate` accepted a target as a positional argument and as `--target`, and when both were
present `--target` won and the positional was discarded without a word.

Measured through the CLI before the fix:

    evaluate <path-that-does-not-exist>                      -> exit 2, clear error
    evaluate --target <repo> <path-that-does-not-exist>      -> exit 0, only <repo> audited,
                                                                stderr carrying nothing but
                                                                the two "Wrote" lines

The same non-existent path is refused when it stands alone and swallowed when it stands beside
`--target`. The shape this takes in practice is an unquoted `TARGETS="a b"` in CI, which
expands to `--target a b` and reports green over a repository nobody looked at.

Refusing is the honest answer rather than picking a winner: the operator named two
repositories and this command audits one. Identical values are allowed through, because
naming the same repository twice expresses one intent and there is nothing to disambiguate.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    target = tmp_path / name
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    return target


def test_two_different_targets_are_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = tmp_path / "out"

    result = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(repo),
            str(tmp_path / "absent"),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out),
        ],
    )

    assert result.exit_code == 2, (
        f"exit {result.exit_code} for a command naming two repositories. The positional was "
        "dropped and the run reported success over a single audit."
    )
    assert not (out / "evaluation-report.json").exists(), (
        "a report was written for the surviving target, which makes the dropped one look audited"
    )
    assert "absent" in result.output, (
        f"the refusal does not say which second target was given: {result.output!r}. An operator "
        "who cannot see the argument that was ignored cannot fix the command."
    )


def test_the_ordinary_forms_are_untouched(tmp_path: Path) -> None:
    """One target, given either way, is the normal invocation and must keep working."""

    repo = _repo(tmp_path)

    for index, argv in enumerate(
        (
            ["evaluate", "--target", str(repo)],
            ["evaluate", str(repo)],
            # The same repository named twice is redundant, not ambiguous.
            ["evaluate", "--target", str(repo), str(repo)],
        )
    ):
        out = tmp_path / f"out-{index}"
        result = runner.invoke(app, [*argv, "--profile", "github-level-1", "--output-dir", str(out)])

        assert result.exit_code == 0, f"{argv} exited {result.exit_code}: {result.output!r}"
        report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
        assert report["target_path"] == repo.name


def test_naming_no_target_at_all_still_explains_itself(tmp_path: Path) -> None:
    """The refusal above must not have replaced the message for giving no target."""

    result = runner.invoke(app, ["evaluate", "--profile", "github-level-1", "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 2
    assert "Two targets" not in result.output, (
        f"the ambiguity message fired when no target was given at all: {result.output!r}"
    )
