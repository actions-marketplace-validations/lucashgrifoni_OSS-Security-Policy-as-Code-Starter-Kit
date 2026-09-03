"""v9.0.2 hotfix regression tests for ``export-evidence`` (unit F3).

Three bugs:

- A: a filesystem error on the ``--output`` path must exit 2 (usage), not 3 (internal
  traceback leak).
- B: ``--validate`` on a contentless report (0 controls) must exit 2 consistently for
  oscal/spdx/sarif (gemara already fails-closed).
- C: the synthesized SARIF must read reports/2.0 ``state``/``message`` (non-empty
  ``message.text``) and populate ``tool.driver.rules`` with one rule per emitted ruleId.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import export_evidence as ee
from oss_policy_kit.cli.main import app

runner = CliRunner()

# reports/2.0-shaped controls: ``state`` + ``message`` (not ``status``/``reason``).
_REPORT_2_0 = {
    "schema_version": "https://example/reports/2.0",
    "target": "C:/tmp/repo",
    "profile": {"id": "github-level-1", "title": "GitHub Level 1"},
    "summary_by_status": {"PASS": 1, "FAIL": 1},
    "controls": [
        {"id": "GOV-SEC-001", "state": "PASS", "message": "policy file present"},
        {"id": "CI-PIN-008", "state": "FAIL", "message": "actions pinned to mutable refs"},
    ],
    "waivers": [],
}

_REPORT_EMPTY = {
    "schema_version": "https://example/reports/2.0",
    "target": "C:/tmp/repo",
    "profile": {"id": "github-level-1", "title": "GitHub Level 1"},
    "summary_by_status": {},
    "controls": [],
    "waivers": [],
}


def _report_at(target: Path, *, report: dict | None = None) -> None:
    out = target / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation-report.json").write_text(json.dumps(report or _REPORT_2_0), encoding="utf-8")


# --- Bug A: unwritable --output exits 2, not 3 ------------------------------


def test_unwritable_output_exits_2_not_3(tmp_path: Path) -> None:
    """An --output that points *into* a regular file (so the parent is not a
    directory) raises OSError on write; it must surface as a usage error (exit 2),
    never an internal traceback (exit 3)."""
    _report_at(tmp_path)
    # A file used as a directory component -> NotADirectoryError (subclass of OSError).
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    bad_output = blocker / "evidence.json"
    res = runner.invoke(
        app,
        ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--output", str(bad_output)],
    )
    assert res.exit_code == 2, res.output
    assert "Unexpected error" not in res.output  # must NOT be the exit-3 last-resort branch


# --- Bug B: contentless report under --validate exits 2 for all formats -----


@pytest.mark.parametrize("fmt", ["oscal", "spdx", "sarif", "gemara"])
def test_contentless_report_validate_exits_2(tmp_path: Path, fmt: str) -> None:
    _report_at(tmp_path, report=_REPORT_EMPTY)
    out = tmp_path / f"ev.{fmt}.json"
    res = runner.invoke(
        app,
        ["export-evidence", "--target", str(tmp_path), "--format", fmt, "--output", str(out), "--validate"],
    )
    assert res.exit_code == 2, f"format {fmt!r} -> {res.exit_code}\n{res.output}"
    assert "Unexpected error" not in res.output
    assert not out.exists()  # fail-closed: nothing written


# --- Bug C: synthesized SARIF carries message.text + populated rules[] -------


def test_sarif_reads_state_and_message_and_populates_rules() -> None:
    """Bug C's original point -- message.text and a populated rules[] -- still holds.

    What changed in v10.0.7 is which controls become results. The PASS assertion this
    test carried (``levels["GOV-SEC-001"] == "note"``) described the defect that turned
    every passing control into a code-scanning alert, so it now asserts the opposite.
    """

    doc = ee._render_sarif(_REPORT_2_0)
    run = doc["runs"][0]
    results = run["results"]

    # message.text comes from reports/2.0 ``message`` (not the absent ``reason``).
    texts = {r["ruleId"]: r["message"]["text"] for r in results}
    assert texts["CI-PIN-008"] == "actions pinned to mutable refs"
    assert "GOV-SEC-001" not in texts, "the passing control was emitted as a result"

    # FAIL is the only actionable state here, and it maps to error.
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["CI-PIN-008"] == "error"

    # rules[] still declares BOTH controls, so omitting the result loses no record.
    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["GOV-SEC-001", "CI-PIN-008"]
    assert ee._validate(doc, "sarif") == []


def test_sarif_command_emits_message_and_rules(tmp_path: Path) -> None:
    _report_at(tmp_path)
    out = tmp_path / "ev.sarif.json"
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--output", str(out)])
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["rules"]  # non-empty rules[]
    assert any(r["message"]["text"] for r in doc["runs"][0]["results"])  # non-empty message.text
