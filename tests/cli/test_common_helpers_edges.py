"""Shared CLI helpers: telling a path from a typo, and honouring the privacy default.

Two decisions here are user-visible in ways that are easy to miss.

`_looks_like_path` decides whether a bare first argument is a target directory or a mistyped
subcommand. Getting it wrong turns `recommend` (a typo for `recommend-profile`) into a
confusing "Not a directory" error instead of "No such command", and the reverse would route a
real target into the command lookup.

`_sanitize_report_for_human_stdout` is the single place `--include-absolute-path` is honoured
for the human summary. Every report written to disk already respects the privacy default, but
`--summary-only` echoed `target_path` and the external waiver path verbatim, printing the
auditor's home directory and OS username to the terminal. The flag must be the only thing that
changes that.

The diagnostic helpers below are best-effort by design: they enrich an error message, so a
failure while collecting the diagnostic must never replace the real error with its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.cli import common

# --------------------------------------------------------------------------- #
# path vs. mistyped subcommand
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "token",
    ["./repo", "repo/sub", "repo\\sub", ".", "..", "~", "~/code", ".hidden", "C:", "C:repo", "D:x"],
)
def test_tokens_that_name_a_location_are_treated_as_paths(token: str) -> None:
    """A separator, a home marker, a dot form, or a drive prefix all mean 'this is a path'."""

    assert common._looks_like_path(token) is True


@pytest.mark.parametrize("token", ["recommend", "evaluat", "profiles-x", "abc"])
def test_a_bare_word_that_is_not_a_location_is_not_a_path(token: str) -> None:
    """Left as a command lookup, so the user gets 'No such command', not a path error."""

    assert common._looks_like_path(token) is False


def test_an_empty_token_reads_as_the_current_directory() -> None:
    """`Path("")` is `.`, which exists, so an empty argv element routes to the target path.

    Pinned rather than changed: an empty first argument is not a case anyone reaches by typing,
    and the surprise worth recording is the Python one -- `Path("").exists()` is True.
    """

    assert common._looks_like_path("") is True


def test_an_existing_directory_name_without_a_separator_is_still_a_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare name that exists on disk is a target, however command-like it looks."""

    (tmp_path / "evaluate").mkdir()
    monkeypatch.chdir(tmp_path)
    assert common._looks_like_path("evaluate") is True


# --------------------------------------------------------------------------- #
# Best-effort diagnostics never raise
# --------------------------------------------------------------------------- #


def test_a_broken_click_context_lookup_yields_no_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """This only enriches an error message; an exception here would replace the real error."""

    import importlib

    def _boom(_name: str) -> object:
        raise RuntimeError("import machinery unavailable")

    monkeypatch.setattr(importlib, "import_module", _boom)
    assert common._current_cli_context() is None


def test_a_parameter_source_lookup_that_raises_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provenance is best-effort; a click version without the API must not break the message."""

    class _Parent:
        def get_parameter_source(self, _name: str) -> object:
            raise RuntimeError("no such API on this click")

    class _Ctx:
        parent = _Parent()

    monkeypatch.setattr(common, "_current_cli_context", lambda: _Ctx())
    assert common._root_flags_typed_before_subcommand() == []


def test_no_cli_context_means_no_typed_root_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "_current_cli_context", lambda: None)
    assert common._root_flags_typed_before_subcommand() == []


# --------------------------------------------------------------------------- #
# Operational warning summary
# --------------------------------------------------------------------------- #


def test_no_warnings_prints_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    common.print_operational_warning_summary([])
    assert capsys.readouterr().err == ""


def test_a_warning_is_printed_with_its_continuation_lines(capsys: pytest.CaptureFixture[str]) -> None:
    """A long warning wraps; every wrapped line has to reach the terminal, not just the first."""

    common.print_operational_warning_summary(["A deliberately long operational warning " * 8])
    err = capsys.readouterr().err
    assert "Operational warnings (1)" in err
    assert err.count("\n") > 2, err


# --------------------------------------------------------------------------- #
# Project config fills only what the CLI did not
# --------------------------------------------------------------------------- #


def _request(**overrides: object) -> common.EvaluateRequest:
    base: dict[str, object] = {
        "target_pos": None,
        "target_opt": ".",
        "profile": None,
        "output_dir": Path("out"),
        "waivers": None,
        "scorecard_json": None,
        "kit_root": None,
        "output_format": "human",
        "summary_only": False,
        "fail_on": "fail",
    }
    base.update(overrides)
    return common.EvaluateRequest(**base)  # type: ignore[arg-type]


def test_a_config_report_contract_is_used_when_the_flag_was_not_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The config fills a setting the user did not pass; an explicit flag always wins."""

    class _Cfg:
        fail_on = "none"
        output_dir = "cfg-out"
        report_json_contract = "2.0"
        profile = "github-level-1"
        path = Path("oss-policy-kit.yaml")

    monkeypatch.setattr(common, "load_project_config_for_target", lambda _root: _Cfg())
    settings = common._resolve_eval_settings(_request(report_json_contract_provided=False), tmp_path)
    assert settings.report_json_contract == "2.0"


def test_an_explicit_report_contract_flag_beats_the_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Cfg:
        fail_on = "none"
        output_dir = "cfg-out"
        report_json_contract = "9.9"
        profile = "github-level-1"
        path = Path("oss-policy-kit.yaml")

    monkeypatch.setattr(common, "load_project_config_for_target", lambda _root: _Cfg())
    req = _request(report_json_contract="2.0", report_json_contract_provided=True)
    assert common._resolve_eval_settings(req, tmp_path).report_json_contract == "2.0"
