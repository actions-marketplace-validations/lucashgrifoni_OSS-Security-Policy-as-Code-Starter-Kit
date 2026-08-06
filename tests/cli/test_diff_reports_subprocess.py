"""Subprocess tests for ``diff-reports`` (Phase 3 drift CLI)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT


def _subprocess_env() -> dict[str, str]:
    """Return a deterministic environment for CLI subprocess tests."""

    env = os.environ.copy()
    for key in (
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONBREAKPOINT",
        "PYTHONINSPECT",
        "PYTHONEXECUTABLE",
    ):
        env.pop(key, None)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "120"
    env["LINES"] = "40"
    env["PYTHONFAULTHANDLER"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    # Same rationale as tests/cli/test_cli_subprocess.py: keep user site visible for typer/click.
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONUTF8"] = "1"
    return env


def _run_module(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "oss_policy_kit", *argv]
    return subprocess.run(
        cmd,
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_subprocess_env(),
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )


def _minimal_report(*, results: list[dict[str, object]], kit_version: str = "3.0.0") -> dict[str, object]:
    """A ``reports/2.0`` payload — the only contract ``diff-reports`` accepts."""

    return {
        "kit_version": kit_version,
        "contract_version": "reports/2.0",
        "profile": {"id": "test"},
        "controls": results,
    }


def _result_row(control_id: str, status: str) -> dict[str, object]:
    """One ``controls[]`` entry. ``status`` is given lowercase for readability at the
    call sites and normalised to the ``reports/2.0`` uppercase ``state`` here."""

    return {
        "id": control_id,
        "title": f"Title {control_id}",
        "category": "governance",
        "state": status.upper().replace("-", "_"),
        "lifecycle": "stable",
        "profile": "p",
        "evidence_sources": [],
        "confidence": "high",
        "reason": "r",
        "remediation": "m",
        "owner": None,
        "expires_at": None,
        "extra": {},
        "waiver": None,
        "evidence_collection_method": "static",
    }


def test_diff_reports_before_missing_exits_2(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    after = tmp_path / "after.json"
    after.write_text(json.dumps(_minimal_report(results=[_result_row("A", "pass")])), encoding="utf-8")
    proc = _run_module(["diff-reports", "--before", str(missing), "--after", str(after)])
    assert proc.returncode == 2
    assert "before" in (proc.stderr + proc.stdout).lower()


def test_diff_reports_no_regression_exits_0(tmp_path: Path) -> None:
    rows = [_result_row("A", "pass"), _result_row("B", "fail")]
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps(_minimal_report(results=list(rows))), encoding="utf-8")
    after.write_text(json.dumps(_minimal_report(results=list(rows), kit_version="3.1.0")), encoding="utf-8")
    proc = _run_module(["diff-reports", "--before", str(before), "--after", str(after), "--format", "json"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload.get("has_regressions") is False


def test_diff_reports_regression_exits_1_by_default(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps(_minimal_report(results=[_result_row("X", "pass")])), encoding="utf-8")
    after.write_text(json.dumps(_minimal_report(results=[_result_row("X", "fail")])), encoding="utf-8")
    proc = _run_module(["diff-reports", "--before", str(before), "--after", str(after)])
    assert proc.returncode == 1, proc.stderr + proc.stdout


def test_diff_reports_regression_no_fail_flag_exits_0(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps(_minimal_report(results=[_result_row("X", "pass")])), encoding="utf-8")
    after.write_text(json.dumps(_minimal_report(results=[_result_row("X", "fail")])), encoding="utf-8")
    proc = _run_module(
        ["diff-reports", "--before", str(before), "--after", str(after), "--no-fail-on-regression", "-f", "table"]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
