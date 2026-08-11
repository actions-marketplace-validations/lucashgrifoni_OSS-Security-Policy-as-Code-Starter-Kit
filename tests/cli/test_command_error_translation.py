"""Every command turns a failure into an exit code the same way, and none leaks a traceback.

Each command wraps its work in the same four-arm block, and the arms are not
interchangeable. A kit error is the user's problem to fix (exit 2, with the message). An OS
error on a user-supplied path is also exit 2, because a missing directory or an unwritable
output is a usage problem, not a bug. A ``typer.Exit`` raised deeper is a verdict a gate
already decided, and must arrive with its own code intact -- flattening it to 1 would turn a
"validation failed" into an indistinguishable generic failure. Anything else is a bug in the
kit, and must still reach the operator as a message rather than a stack trace, because a
traceback in a CI log names files on the machine that ran it and helps nobody reading it.

That block is duplicated across the command surface, so it is tested across the command
surface: one table, every command that has a separable runner. Testing it once would leave the
other copies free to drift, which is exactly what happened -- most of these arms had never
executed.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()

#: (command name, module, runner attribute, CLI args). Not every command takes `--target`;
#: the args are exactly what each one needs to reach its own body.
_COMMANDS: list[tuple[str, str, str, list[str]]] = [
    ("emit-insights", "oss_policy_kit.cli.emit_insights", "_run_emit_insights", ["--target", "{tmp}"]),
    ("export-policy", "oss_policy_kit.cli.export_policy", "_run_export_policy", ["--profile", "github-level-1"]),
    ("scan-k8s", "oss_policy_kit.cli.scan_k8s", "_run_scan_k8s", ["--target", "{tmp}"]),
    ("ingest-scorecard", "oss_policy_kit.cli.ingest_scorecard", "_run_ingest_scorecard", ["--target", "{tmp}"]),
    ("ingest-insights", "oss_policy_kit.cli.ingest_insights", "_run_ingest_insights", ["--target", "{tmp}"]),
    ("diff-catalogs", "oss_policy_kit.cli.diff_catalogs", "_run_diff_catalogs", ["--from", "{tmp}"]),
    ("osps-coverage", "oss_policy_kit.cli.osps_coverage", "_run_osps_coverage", []),
]

_IDS = [c[0] for c in _COMMANDS]


def _patch_runner(monkeypatch: pytest.MonkeyPatch, module_name: str, attr: str, exc: BaseException) -> None:
    module = importlib.import_module(module_name)

    def _raise(*_a: object, **_k: object) -> object:
        raise exc

    monkeypatch.setattr(module, attr, _raise)


def _invoke(command: str, extra: list[str], tmp_path: Path) -> object:
    args = [a.replace("{tmp}", str(tmp_path)) for a in extra]
    return runner.invoke(app, [command, *args])


@pytest.mark.parametrize(("command", "module", "attr", "extra"), _COMMANDS, ids=_IDS)
def test_a_kit_error_exits_two_with_a_message(
    command: str, module: str, attr: str, extra: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The user can act on this one, so it gets the message and the usage exit code."""

    _patch_runner(monkeypatch, module, attr, InvalidInputError("the input was not usable"))
    res = _invoke(command, extra, tmp_path)
    assert res.exit_code == 2, res.output  # type: ignore[attr-defined]
    assert "not usable" in res.output  # type: ignore[attr-defined]
    assert "Traceback" not in res.output  # type: ignore[attr-defined]


@pytest.mark.parametrize(("command", "module", "attr", "extra"), _COMMANDS, ids=_IDS)
def test_a_deliberate_exit_keeps_its_own_code(
    command: str, module: str, attr: str, extra: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate's verdict must not be flattened into a generic failure by the catch-all."""

    _patch_runner(monkeypatch, module, attr, typer.Exit(code=7))
    res = _invoke(command, extra, tmp_path)
    assert res.exit_code == 7, res.output  # type: ignore[attr-defined]


@pytest.mark.parametrize(("command", "module", "attr", "extra"), _COMMANDS, ids=_IDS)
def test_an_unexpected_error_never_prints_a_traceback(
    command: str, module: str, attr: str, extra: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug in the kit is still the operator's log entry; a stack trace helps nobody there."""

    _patch_runner(monkeypatch, module, attr, RuntimeError("nobody anticipated this"))
    res = _invoke(command, extra, tmp_path)
    assert res.exit_code != 0  # type: ignore[attr-defined]
    assert "Traceback" not in res.output, res.output  # type: ignore[attr-defined]


@pytest.mark.parametrize(("command", "module", "attr", "extra"), _COMMANDS, ids=_IDS)
def test_a_filesystem_error_on_a_user_path_is_a_usage_error(
    command: str, module: str, attr: str, extra: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unwritable --output or a vanished --target is the user's problem, not a crash."""

    _patch_runner(monkeypatch, module, attr, OSError(13, "Permission denied"))
    res = _invoke(command, extra, tmp_path)
    assert res.exit_code != 0  # type: ignore[attr-defined]
    assert "Traceback" not in res.output, res.output  # type: ignore[attr-defined]
