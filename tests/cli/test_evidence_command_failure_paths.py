"""How the evidence commands fail: which exit code, and what the operator is told.

The kit spends these two exit codes deliberately. `2` means *you can fix this* -- a missing
token, an unwritable directory, an argument the command cannot use. `3` means *the kit
misbehaved*, and it is the code an adopter is entitled to open an issue about. Sorting a failure
into the wrong one wastes somebody's afternoon either way, so each handler below is asserted on
the code it produces and on the absence of a traceback in what reaches the terminal.

One invariant runs through all of it: an exit code chosen deeper in the stack survives. The
`except typer.Exit: raise` arms exist so a deliberate exit is not caught by the broad handler
below them and re-labelled as an internal error.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from oss_policy_kit.cli import evidence as ev
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()


# --------------------------------------------------------------------------- #
# scaffold-evidence
# --------------------------------------------------------------------------- #


def test_a_deliberate_exit_from_deeper_in_the_stack_is_not_relabelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the re-raise, the broad handler below would turn this into exit 3."""

    def _exit(*_a: object, **_k: object) -> object:
        raise typer.Exit(code=7)

    monkeypatch.setattr(ev, "scaffold_evidence_files", _exit)
    result = runner.invoke(app, ["scaffold-evidence", "--target", str(tmp_path), "--platform", "github"])

    assert result.exit_code == 7


def test_an_unexpected_failure_reaches_the_operator_as_a_message_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit 3 is the kit admitting fault; it still owes the operator a readable line."""

    def _boom(*_a: object, **_k: object) -> object:
        raise ZeroDivisionError("scaffolding went sideways")

    monkeypatch.setattr(ev, "scaffold_evidence_files", _boom)
    result = runner.invoke(app, ["scaffold-evidence", "--target", str(tmp_path), "--platform", "github"])

    assert result.exit_code == 3
    assert "Traceback" not in result.output
    assert str(tmp_path) not in result.output


def test_a_target_that_is_a_file_is_a_usage_error_not_an_internal_one(tmp_path: Path) -> None:
    """The adopter mistyped a path; that is theirs to fix, so it exits 2."""

    target = tmp_path / "not-a-dir"
    target.write_text("x", encoding="utf-8")
    result = runner.invoke(app, ["scaffold-evidence", "--target", str(target), "--platform", "github"])

    assert result.exit_code == 2
    assert "Traceback" not in result.output


# --------------------------------------------------------------------------- #
# collect-evidence
# --------------------------------------------------------------------------- #


def test_a_missing_optional_extra_is_a_usage_error_with_its_own_fix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Collectors signal it as `RuntimeError(...) from ImportError`, and that is correctable."""

    class _NeedsExtra:
        def collect(self, _slug: str) -> object:
            raise RuntimeError("install oss-policy-kit[github]") from ImportError("no module named httpx")

    monkeypatch.setattr(ev, "_build_evidence_collector", lambda *_a, **_k: (_NeedsExtra(), "org/repo"))
    result = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github"])

    assert result.exit_code == 2
    assert "oss-policy-kit[github]" in result.output
    assert "Unexpected error" not in result.output


def test_a_runtime_error_that_is_not_the_missing_extra_signal_is_an_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counterpart, and the reason the cause is inspected rather than the type alone.

    Treating every `RuntimeError` as a missing dependency would tell an adopter to `pip install`
    their way out of a genuine bug in the collector.
    """

    class _Broken:
        def collect(self, _slug: str) -> object:
            raise RuntimeError("collector lost its mind")

    monkeypatch.setattr(ev, "_build_evidence_collector", lambda *_a, **_k: (_Broken(), "org/repo"))
    result = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github"])

    assert result.exit_code == 3
    assert "Traceback" not in result.output


def test_a_deliberate_exit_while_writing_evidence_is_not_relabelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Ok:
        def collect(self, _slug: str) -> list[object]:
            return []

    def _exit(*_a: object, **_k: object) -> object:
        raise typer.Exit(code=9)

    monkeypatch.setattr(ev, "_build_evidence_collector", lambda *_a, **_k: (_Ok(), "org/repo"))
    monkeypatch.setattr(ev, "_write_collected_evidence", _exit)
    result = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "github"])

    assert result.exit_code == 9


# --------------------------------------------------------------------------- #
# GitLab project identity
# --------------------------------------------------------------------------- #


def test_gitlab_refuses_to_guess_which_project_to_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    """There is no sensible default here, and collecting the wrong project is silent."""

    monkeypatch.setitem(os.environ, "GITLAB_TOKEN", "glpat-token")
    monkeypatch.delenv("GITLAB_PROJECT", raising=False)

    with pytest.raises(InvalidInputError, match="--repo group/project"):
        ev._gitlab_collector(None)


def test_gitlab_takes_the_project_from_the_environment_when_the_flag_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The counterpart: CI sets `GITLAB_PROJECT`, and requiring the flag anyway would be noise."""

    monkeypatch.setitem(os.environ, "GITLAB_TOKEN", "glpat-token")
    monkeypatch.setitem(os.environ, "GITLAB_PROJECT", "group/project")

    _collector, slug = ev._gitlab_collector(None)
    assert slug == "group/project"


def test_an_explicit_repo_flag_wins_over_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(os.environ, "GITLAB_TOKEN", "glpat-token")
    monkeypatch.setitem(os.environ, "GITLAB_PROJECT", "group/from-env")

    _collector, slug = ev._gitlab_collector("group/from-flag")
    assert slug == "group/from-flag"


# --------------------------------------------------------------------------- #
# Dry-run preview
# --------------------------------------------------------------------------- #


def test_the_dry_run_preview_omits_sections_it_has_nothing_to_put_in(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """What a platform gets on the day it joins `--platform` before its preview table does.

    The command validates `--platform` first, so every value it forwards today has both tables
    filled in; this is asserted at the helper because the guards are what keep a half-registered
    platform from printing a "Would create:" heading with nothing under it.
    """

    ev._print_collect_dry_run_preview(
        target=tmp_path,
        target_display=str(tmp_path),
        platform="bitbucket",
        repo_slug=None,
        output_dir=None,
    )
    out = capsys.readouterr().out

    assert "Would create:" not in out
    assert "Environment probe" not in out
    assert "not detected" in out, "the operator still has to be told the repo slug is missing"


def test_an_unsupported_platform_never_reaches_the_preview(tmp_path: Path) -> None:
    """A dry run that quietly previewed nothing would read as "there is nothing to collect"."""

    result = runner.invoke(app, ["collect-evidence", "--target", str(tmp_path), "--platform", "bitbucket", "--dry-run"])

    assert result.exit_code == 2
    assert "Unsupported --platform" in result.output
