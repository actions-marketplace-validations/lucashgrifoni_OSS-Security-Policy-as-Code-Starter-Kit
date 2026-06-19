"""CLI tests for the ``ingest-scorecard`` subcommand (T2.3)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.scorecard_ingest import MappedCheck, ScorecardIngestReport
from oss_policy_kit.cli.ingest_scorecard import _render_human
from oss_policy_kit.cli.main import app

ROOT = Path(__file__).parents[2]
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_runner = CliRunner()

_FIXTURE = {
    "date": "2026-06-01T00:00:00Z",
    "score": 7.3,
    "checks": [
        {"name": "Token-Permissions", "score": 9, "reason": "read-only"},
        {"name": "Branch-Protection", "score": 8, "reason": "protected"},
        {"name": "SAST", "score": 6, "reason": "codeql"},
        {"name": "License", "score": 10, "reason": "ok"},
        {"name": "Dangerous-Workflow", "score": 10, "reason": "clean"},
        {"name": "Code-Review", "score": 9, "reason": "reviewed"},
    ],
}


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "200"
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )


def _seed(target: Path, data: dict[str, object] | None = None) -> Path:
    ev = target / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    path = ev / "scorecard-result.json"
    path.write_text(json.dumps(data if data is not None else _FIXTURE), encoding="utf-8")
    return path


def test_cli_help_lists_ingest_scorecard() -> None:
    proc = _run(["--help"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "ingest-scorecard" in "".join(_ANSI_RE.sub("", proc.stdout + proc.stderr).split())


def test_cli_human_maps_controls_and_is_honest(tmp_path: Path) -> None:
    seeded = _seed(tmp_path)
    proc = _run(["ingest-scorecard", "--input", str(seeded), "--target", str(tmp_path)])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    out = proc.stdout
    assert "CI-PERM-006" in out  # a mapped control id is shown
    assert "SEC-CODEQL-010" in out  # SAST -> CodeQL control
    assert "verbatim" in out
    assert "never elevates" in out and "changes no" in out and "evaluate" in out  # honesty note


def test_cli_json_shape(tmp_path: Path) -> None:
    seeded = _seed(tmp_path)
    proc = _run(["ingest-scorecard", "--input", str(seeded), "--target", str(tmp_path), "--format", "json"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["aggregate_score"] == 7.3
    assert "corroborated_controls" in payload
    assert len(payload["mapped_checks"]) >= 6


def test_cli_not_found_exits_0(tmp_path: Path) -> None:
    res = _runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path)])
    assert res.exit_code == 0, res.output
    assert "none found" in res.output


def test_cli_invalid_file_exits_1(tmp_path: Path) -> None:
    bad = _seed(tmp_path, data=None)
    bad.write_text("{ this is not json", encoding="utf-8")
    res = _runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path)])
    assert res.exit_code == 1, res.output


def test_cli_bad_format_exits_2(tmp_path: Path) -> None:
    _seed(tmp_path)
    res = _runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path), "--format", "xml"])
    assert res.exit_code == 2, res.output


# --- direct render-branch coverage (deterministic, no wall-clock dependency) --- #


def _report(freshness: str) -> ScorecardIngestReport:
    mapped = (
        MappedCheck("Token-Permissions", "CI-PERM-006", "note", present=True, score=9, reason="ok"),
        MappedCheck("Fuzzing", "SEC-FUZZ-001", "note", present=False, score=None, reason=None),
    )
    return ScorecardIngestReport(
        found=True,
        input_path="scorecard-result.json",
        result_date="2026-06-01T00:00:00Z",
        freshness=freshness,
        aggregate_score=7.3,
        mapped=mapped,
    )


def test_render_human_fresh_branch(capsys: pytest.CaptureFixture[str]) -> None:
    _render_human(_report("fresh"))
    out = capsys.readouterr().out
    assert "Corroborated" in out and "CI-PERM-006" in out


def test_render_human_stale_branch(capsys: pytest.CaptureFixture[str]) -> None:
    _render_human(_report("stale"))
    out = capsys.readouterr().out
    assert "STALE" in out


def test_render_human_undated_branch(capsys: pytest.CaptureFixture[str]) -> None:
    _render_human(_report("undated"))
    out = capsys.readouterr().out
    assert "nothing corroborated" in out
