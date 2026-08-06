"""In-process branch coverage for the ``diff-reports`` error and exit-code paths.

The existing diff-reports tests run via subprocess (``test_diff_reports_subprocess.py``),
which is not coverage-instrumented and therefore does not exercise the handler branches
for the coverage gate. These ``CliRunner`` tests drive the same exit-code contract
in-process so the error handlers are both verified and measured:

    0  no regressions (or regressions suppressed)
    1  regressions present and --fail-on-regression (default)
    2  bad --format, missing/unreadable report, or non-object report (ValueError)
    3  unexpected internal error
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import reports as rep
from oss_policy_kit.cli.main import app

runner = CliRunner()


def _report(controls: list[dict[str, str]], *, profile_id: str = "p") -> dict[str, Any]:
    """A ``reports/2.0`` payload — the only contract ``diff-reports`` accepts.

    This helper used to emit ``reports/0.2`` with ``results``/``control_id``/``status``.
    Those fixtures kept passing after v9.0.0 removed the pre-2.0 contracts, which is how
    ``diff-reports`` shipped blind to every report the kit produces.
    """

    return {
        "contract_version": "reports/2.0",
        "profile": {"id": profile_id},
        "controls": controls,
    }


def _write(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_before_not_found_exits_2(tmp_path: Path) -> None:
    after = tmp_path / "after.json"
    _write(after, _report([{"id": "A", "state": "PASS"}]))
    res = runner.invoke(app, ["diff-reports", "--before", str(tmp_path / "nope.json"), "--after", str(after)])
    assert res.exit_code == 2, res.output


def test_after_not_found_exits_2(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    _write(before, _report([{"id": "A", "state": "PASS"}]))
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(tmp_path / "nope.json")])
    assert res.exit_code == 2, res.output


def test_non_object_report_exits_2(tmp_path: Path) -> None:
    # load_report_json raises ValueError for a non-object root (caught separately from
    # OssPolicyKitError) -> clean exit 2, not an internal crash.
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text("[1, 2, 3]", encoding="utf-8")
    _write(after, _report([{"id": "A", "state": "PASS"}]))
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after), "--format", "json"])
    assert res.exit_code == 2, res.output


def test_malformed_json_report_exits_2(tmp_path: Path) -> None:
    # json.JSONDecodeError is a subclass of ValueError -> same exit-2 path.
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text("{not json", encoding="utf-8")
    _write(after, _report([{"id": "A", "state": "PASS"}]))
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after)])
    assert res.exit_code == 2, res.output


def test_profile_mismatch_warns_exit_0(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write(before, _report([{"id": "A", "state": "PASS"}], profile_id="github-level-1"))
    _write(after, _report([{"id": "A", "state": "PASS"}], profile_id="github-level-2"))
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after), "--format", "json"])
    assert res.exit_code == 0, res.output


def test_regression_exits_1_by_default(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write(before, _report([{"id": "X", "state": "PASS"}]))
    _write(after, _report([{"id": "X", "state": "FAIL"}]))
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after), "--format", "json"])
    assert res.exit_code == 1, res.output


def test_regression_suppressed_exits_0(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write(before, _report([{"id": "X", "state": "PASS"}]))
    _write(after, _report([{"id": "X", "state": "FAIL"}]))
    res = runner.invoke(
        app,
        [
            "diff-reports",
            "--before",
            str(before),
            "--after",
            str(after),
            "--no-fail-on-regression",
            "--format",
            "json",
        ],
    )
    assert res.exit_code == 0, res.output


def test_unexpected_error_exits_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-OssPolicyKitError, non-ValueError failure hits the last-resort handler -> exit 3
    # with a user message, never a leaked traceback.
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write(before, _report([{"id": "A", "state": "PASS"}]))
    _write(after, _report([{"id": "A", "state": "PASS"}]))

    def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(rep, "compute_drift", _boom)
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after)])
    assert res.exit_code == 3, res.output
