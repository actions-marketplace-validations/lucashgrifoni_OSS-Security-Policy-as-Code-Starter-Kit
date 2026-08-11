"""The root callback's own flags, and what `init` prints when there is little to say.

`_flag_was_provided` decides whether a value came from the command line or from a Typer
default, and that decision is what lets a project config fill a setting the user did not pass
while an explicit flag still wins. It reads provenance through an optional Click API, so it is
written to answer "no" rather than raise when the API is missing or returns nothing -- a
version skew there must not take the CLI down over a question that only affects precedence.

`init`'s output helpers are covered for the cases where the sections are empty. A dry run that
would write nothing still has to say "(no actions)" rather than print a bare heading, because a
heading with nothing under it reads as a rendering bug, not as a result.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import evaluate as ev
from oss_policy_kit.cli import init as init_mod
from oss_policy_kit.cli.main import app

runner = CliRunner()


# --------------------------------------------------------------------------- #
# Flag provenance
# --------------------------------------------------------------------------- #


def test_a_click_context_without_the_provenance_api_answers_no() -> None:
    """An older or vendored Click may not expose it; that is not a reason to crash."""

    class _Ctx:
        def get_parameter_source(self, _name: str) -> object:
            raise RuntimeError("no such API")

    assert ev._flag_was_provided(cast(Any, _Ctx()), "fail_on") is False


def test_an_unknown_parameter_answers_no() -> None:
    """No provenance means we cannot claim the user typed it, so the config may fill it."""

    class _Ctx:
        def get_parameter_source(self, _name: str) -> None:
            return None

    assert ev._flag_was_provided(cast(Any, _Ctx()), "fail_on") is False


@pytest.mark.parametrize(
    ("source_name", "expected"),
    [("COMMANDLINE", True), ("ENVIRONMENT", True), ("DEFAULT", False)],
)
def test_only_a_typer_default_counts_as_not_provided(source_name: str, expected: bool) -> None:
    """Comparing by name, not by class: Typer vendors its own Click and `!=` on the
    imported enum would always be true."""

    class _Ctx:
        def get_parameter_source(self, _name: str) -> object:
            return SimpleNamespace(name=source_name)

    assert ev._flag_was_provided(cast(Any, _Ctx()), "fail_on") is expected


# --------------------------------------------------------------------------- #
# Root callback flags
# --------------------------------------------------------------------------- #


def test_the_debug_flag_turns_on_debug_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[bool] = []
    monkeypatch.setattr(ev, "enable_debug_logging", lambda: called.append(True))
    res = runner.invoke(app, ["--debug", "--version"])
    assert res.exit_code == 0, res.output
    assert called == [True]


def test_the_version_flag_prints_the_version_and_exits() -> None:
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0, res.output
    assert res.stdout.strip()


def test_a_catalog_that_will_not_load_makes_show_profiles_exit_two(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deprecated flag still has to fail like the rest of the CLI, not traceback."""

    from oss_policy_kit.domain.errors import LoadError

    def _boom(**_k: object) -> None:
        raise LoadError("catalog.yaml is not readable")

    monkeypatch.setattr(ev, "_print_profiles_table", _boom)
    res = runner.invoke(app, ["--show-profiles"])
    assert res.exit_code == 2, res.output
    assert "not readable" in res.output
    assert "Traceback" not in res.output


# --------------------------------------------------------------------------- #
# init output with nothing to report
# --------------------------------------------------------------------------- #


def _outcome(**overrides: Any) -> Any:
    base: dict[str, Any] = {"created": [], "overwritten": [], "skipped": [], "next_steps": []}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_a_plan_that_writes_nothing_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    """A heading with nothing under it reads as a rendering bug rather than a result."""

    init_mod._print_init_actions(_outcome(), dry_run=True)
    out = capsys.readouterr().out
    assert "(no actions)" in out


def test_a_plan_that_writes_something_lists_it(capsys: pytest.CaptureFixture[str]) -> None:
    init_mod._print_init_actions(_outcome(created=["oss-policy-kit.yaml"]), dry_run=True)
    out = capsys.readouterr().out
    assert "oss-policy-kit.yaml" in out
    assert "(no actions)" not in out


def test_next_steps_are_printed_when_there_are_any(capsys: pytest.CaptureFixture[str]) -> None:
    plan = SimpleNamespace(notes=[])
    init_mod._print_init_notes_and_steps(plan, _outcome(next_steps=["run evaluate"]))
    out = capsys.readouterr().out
    assert "Next steps" in out
    assert "run evaluate" in out


def test_no_notes_and_no_next_steps_print_no_headings(capsys: pytest.CaptureFixture[str]) -> None:
    plan = SimpleNamespace(notes=[])
    init_mod._print_init_notes_and_steps(plan, _outcome())
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------------------- #
# init --interactive
# --------------------------------------------------------------------------- #


class _SysWithTty:
    """Shadows the module-level `sys` so the TTY answer survives CliRunner's stdin swap.

    `CliRunner` replaces `sys.stdin` when it isolates the invocation, which happens after any
    monkeypatch on the real `sys.stdin` -- so patching that has no effect from a test.
    """

    def __init__(self, real: Any, is_tty: bool) -> None:
        self._real = real
        self._is_tty = is_tty

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    @property
    def stdin(self) -> Any:
        return SimpleNamespace(isatty=lambda: self._is_tty)


def _github_repo(root: Any) -> Any:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text("name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n", encoding="utf-8")
    return root


def test_interactive_init_offers_the_recommended_profile(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The prompt only appears on a real terminal; CI and pipes must never block on it."""

    import sys as _sys

    monkeypatch.setattr(init_mod, "sys", _SysWithTty(_sys, True))
    asked: list[str] = []

    def _prompt(text: str, **_k: object) -> str:
        asked.append(text)
        return ""

    monkeypatch.setattr(init_mod.typer, "prompt", _prompt)
    res = runner.invoke(app, ["init", "--target", str(_github_repo(tmp_path)), "--interactive", "--dry-run"])

    assert res.exit_code == 0, res.output
    assert asked, "the operator was never prompted"
    assert "press Enter to accept" in asked[0]


def test_interactive_init_accepts_a_typed_profile(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys as _sys

    monkeypatch.setattr(init_mod, "sys", _SysWithTty(_sys, True))
    monkeypatch.setattr(init_mod.typer, "prompt", lambda *_a, **_k: "  github-level-2  ")
    res = runner.invoke(app, ["init", "--target", str(_github_repo(tmp_path)), "--interactive", "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "github-level-2" in res.output


def test_a_non_interactive_stdin_never_prompts(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The counterpart: piping into `init` must not hang waiting for an answer."""

    import sys as _sys

    monkeypatch.setattr(init_mod, "sys", _SysWithTty(_sys, False))

    def _never(*_a: object, **_k: object) -> str:
        raise AssertionError("prompted with a non-TTY stdin")

    monkeypatch.setattr(init_mod.typer, "prompt", _never)
    res = runner.invoke(app, ["init", "--target", str(_github_repo(tmp_path)), "--interactive", "--dry-run"])
    assert res.exit_code == 0, res.output


def test_a_deliberate_exit_from_init_keeps_its_code(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import typer as typer_mod

    def _exit_seven(**_k: object) -> object:
        raise typer_mod.Exit(code=7)

    monkeypatch.setattr(init_mod, "build_init_plan", _exit_seven)
    res = runner.invoke(app, ["init", "--target", str(tmp_path), "--dry-run"])
    assert res.exit_code == 7, res.output
