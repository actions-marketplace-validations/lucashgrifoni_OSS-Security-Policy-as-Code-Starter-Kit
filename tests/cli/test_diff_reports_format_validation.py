"""``diff-reports --format`` validation.

Every other subcommand rejects an unknown ``--format`` with exit 2. ``diff-reports``
used to pass the value straight to ``render_drift_report``, which silently fell back to
the Rich table for anything that was not ``json``/``markdown``/``md`` — so a typo like
``--format markdwn`` produced an ANSI table at exit 0 and could corrupt a CI artifact.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

_MINIMAL_REPORT = {
    "schema_version": "https://example/reports/1.0",
    "profile": {"id": "github-level-1"},
    "results": [{"control_id": "A", "status": "pass"}],
}


def _write_report(path: Path) -> None:
    path.write_text(json.dumps(_MINIMAL_REPORT), encoding="utf-8")


def test_diff_reports_rejects_unknown_format(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write_report(before)
    _write_report(after)
    res = runner.invoke(app, ["diff-reports", "--before", str(before), "--after", str(after), "--format", "xml"])
    assert res.exit_code == 2, res.output


def test_diff_reports_accepts_each_valid_format(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _write_report(before)
    _write_report(after)
    for fmt in ("table", "json", "markdown", "md", "JSON", "Markdown"):
        res = runner.invoke(
            app,
            ["diff-reports", "--before", str(before), "--after", str(after), "--format", fmt],
        )
        # No regressions in identical reports -> exit 0 for every accepted format.
        assert res.exit_code == 0, f"format {fmt!r} -> {res.exit_code}\n{res.output}"
