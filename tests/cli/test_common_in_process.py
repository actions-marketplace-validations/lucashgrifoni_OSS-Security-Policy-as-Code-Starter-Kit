"""In-process branch coverage for cli/common.py rendering + IO helpers.

The root-group ``format_help`` override, the ``write_stdout_text`` encoding
fallback, and the human-table / summary-only / sarif evaluate-render branches
are otherwise only exercised through ``subprocess`` (separate interpreter) or a
real TTY, so they don't reach coverage. These drive them in-process: the Typer
command via ``CliRunner`` against the bundled hardened example, plus direct calls
with monkeypatched ``sys.stdout`` / ``write_reports`` / plugin loader.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
from tests.conftest import EXAMPLE_HARDENED
from typer.testing import CliRunner

from oss_policy_kit.cli import common
from oss_policy_kit.cli.main import app

runner = CliRunner()


# --------------------------------------------------------------------------- #
# OssPolicyKitTyperGroup.format_help — rich + non-rich paths
# --------------------------------------------------------------------------- #


def test_root_help_rich_path() -> None:
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "oss-policy-kit" in res.output


def test_root_help_non_rich_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the plain (non-Rich) formatter branch that prepends the ASCII banner
    # via write_cli_banner_to_formatter and defers to Click's super().format_help.
    monkeypatch.setattr(common, "HAS_RICH", False)
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "Usage" in res.output or "evaluate" in res.output


# --------------------------------------------------------------------------- #
# write_stdout_text — UnicodeEncodeError fallback
# --------------------------------------------------------------------------- #


class _RaisingStdout:
    """stdout stub whose .write raises UnicodeEncodeError; optional .buffer."""

    def __init__(self, with_buffer: bool) -> None:
        if with_buffer:
            self.buffer = io.BytesIO()

    def write(self, s: str) -> int:
        raise UnicodeEncodeError("utf-8", s, 0, 1, "cp1252 can't encode")


def test_write_stdout_text_buffer_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    stub = _RaisingStdout(with_buffer=True)
    monkeypatch.setattr(sys, "stdout", stub)
    common.write_stdout_text("café ✓\n")
    assert stub.buffer.getvalue() == "café ✓\n".encode()


def test_write_stdout_text_no_buffer_reraises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _RaisingStdout(with_buffer=False))
    with pytest.raises(UnicodeEncodeError):
        common.write_stdout_text("café\n")


# --------------------------------------------------------------------------- #
# evaluate render branches (human table / preface / summary-only / sarif)
# --------------------------------------------------------------------------- #


def _evaluate(args: list[str]) -> object:
    return runner.invoke(app, ["evaluate", "--target", str(EXAMPLE_HARDENED), "--profile", "github-level-1", *args])


def test_evaluate_default_human_table(tmp_path: Path) -> None:
    res = _evaluate(["--output-dir", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output
    assert "Summary:" in res.output


def test_evaluate_human_table_with_tty_preface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the human-TTY branch so print_evaluate_executive_preface runs in-process.
    monkeypatch.setattr(common.terminal_ui, "human_tty_stdout", lambda: True)
    monkeypatch.setattr(common.terminal_ui, "stream_supports_unicode", lambda stream: True)
    res = _evaluate(["--output-dir", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output


def test_evaluate_summary_only_human(tmp_path: Path) -> None:
    res = _evaluate(["--summary-only", "--output-dir", str(tmp_path / "o")])
    assert res.exit_code == 0, res.output


def test_evaluate_with_sarif_output(tmp_path: Path) -> None:
    out = tmp_path / "o"
    res = _evaluate(["--output-dir", str(out), "--sarif-output", "findings.sarif.json"])
    assert res.exit_code == 0, res.output
    assert (out / "findings.sarif.json").is_file()
    assert "findings.sarif.json" in res.output


def test_evaluate_write_reports_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(common, "write_reports", _boom)
    res = _evaluate(["--output-dir", str(tmp_path / "o")])
    assert res.exit_code != 0
    assert "Cannot write to --output-dir" in res.output


# --------------------------------------------------------------------------- #
# _emit_plugin_load_warnings
# --------------------------------------------------------------------------- #


def test_emit_plugin_load_warnings_with_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "oss_policy_kit.application.evaluators.plugin_load_errors",
        lambda: [{"name": "acme_ev", "kind": "import-error", "detail": "no module named acme"}],
    )
    common._emit_plugin_load_warnings()
    err = capsys.readouterr().err
    assert "acme_ev" in err
    assert "import-error" in err


def test_emit_plugin_load_warnings_no_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("oss_policy_kit.application.evaluators.plugin_load_errors", lambda: [])
    common._emit_plugin_load_warnings()
    assert capsys.readouterr().err == ""
