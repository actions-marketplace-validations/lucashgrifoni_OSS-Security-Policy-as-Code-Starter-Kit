"""Report entries the renderers must tolerate, and how `--validate` reports a refusal.

An evaluation report reaching `export-evidence` may have been produced by an older kit, edited
by hand, or merged by a script. Its `controls` list can therefore hold an entry that is not an
object, or one with no id, or the same control twice. None of those may crash the export or
silently produce a document that claims more than the report said -- an evidence bundle is the
artifact an auditor reads, so a renderer that quietly drops or invents an entry is worse than
one that refuses.

The second half is the exit contract. `--validate` failing is exit 1 with each problem named on
stderr; a `typer.Exit` raised deeper must pass through with its own code; anything unexpected
becomes a clean exit with no traceback, because a stack trace leaks absolute paths from the
machine that ran it and tells the operator nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import export_evidence as ee
from oss_policy_kit.cli.main import app

runner = CliRunner()


def _report(controls: list[Any]) -> dict[str, Any]:
    return {
        "schema_version": "https://example/reports/2.0",
        "generated_at": "2026-08-11T00:00:00Z",
        "kit_version": "10.0.11",
        "target_path": "repo",
        "profile": {"id": "github-level-1", "title": "T"},
        "summary_by_status": {"pass": 1},
        "controls": controls,
    }


def _write_report(root: Path, controls: list[Any]) -> Path:
    path = root / "report.json"
    path.write_text(json.dumps(_report(controls)), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Control entries the renderers must tolerate
# --------------------------------------------------------------------------- #


def test_a_control_entry_that_is_not_an_object_is_skipped_by_sarif() -> None:
    """A stray string in `controls` must not become a rule or take the render down."""

    rendered = ee._render_sarif(_report(["not-a-control", {"id": "GOV-SEC-001", "state": "pass"}]))
    rules = rendered["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["GOV-SEC-001"]


def test_the_same_control_listed_twice_produces_one_rule() -> None:
    """A rule advertises what the tool checked; listing it twice would double-count coverage."""

    duplicated = [{"id": "GOV-SEC-001", "state": "fail"}, {"id": "GOV-SEC-001", "state": "fail"}]
    rendered = ee._render_sarif(_report(duplicated))
    rules = rendered["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["GOV-SEC-001"], rules
    assert len(rendered["runs"][0]["results"]) == 2, "both findings should still be reported"


def test_a_passing_control_without_an_id_is_not_counted_as_a_non_finding() -> None:
    """`_non_finding_control_ids` keys off the id; a blank one has nothing to key on."""

    ids = ee._non_finding_control_ids(_report([{"state": "pass"}, {"id": "  ", "state": "pass"}]))
    assert ids == frozenset()


def test_passing_controls_with_ids_are_collected() -> None:
    """The counterpart, so the test above cannot pass by always returning an empty set."""

    ids = ee._non_finding_control_ids(_report([{"id": "GOV-SEC-001", "state": "pass"}]))
    assert ids == frozenset({"GOV-SEC-001"})


# --------------------------------------------------------------------------- #
# OSCAL validation on a payload of the wrong shape
# --------------------------------------------------------------------------- #


def test_oscal_validation_does_not_crash_when_the_first_result_is_not_an_object() -> None:
    """A hand-edited bundle can hold a string here; the checks below it must be skipped."""

    errs = ee._validate_oscal({"assessment-results": {"metadata": {}, "results": ["not-an-object"]}})
    assert not any("assessment-subjects" in e for e in errs), errs


def test_oscal_validation_reports_a_missing_assessment_subject() -> None:
    """The counterpart: with a real object, the inner checks do run."""

    errs = ee._validate_oscal({"assessment-results": {"metadata": {}, "results": [{}]}})
    assert any("assessment-subjects" in e for e in errs), errs


# --------------------------------------------------------------------------- #
# Exit contract
# --------------------------------------------------------------------------- #


def test_validation_failures_are_listed_and_exit_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Each problem is named: 'validation failed' alone gives the operator nothing to fix."""

    report = _write_report(tmp_path, [{"id": "GOV-SEC-001", "state": "pass"}])
    monkeypatch.setattr(ee, "_validate", lambda _rendered, _fmt: ["oscal: first problem", "oscal: second problem"])

    res = runner.invoke(
        app,
        [
            "export-evidence",
            "--target",
            str(tmp_path),
            "--report",
            str(report),
            "--format",
            "oscal",
            "--output",
            str(tmp_path / "out.json"),
            "--validate",
        ],
    )
    assert res.exit_code == 1, res.output
    assert "first problem" in res.output
    assert "second problem" in res.output


def test_a_deliberate_exit_keeps_its_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import typer

    def _exit_seven(*_a: object, **_k: object) -> object:
        raise typer.Exit(code=7)

    monkeypatch.setattr(ee, "_run_export_evidence", _exit_seven)
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path)])
    assert res.exit_code == 7, res.output


def test_an_unexpected_error_does_not_print_a_traceback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("nobody anticipated this")

    monkeypatch.setattr(ee, "_run_export_evidence", _boom)
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path)])
    assert res.exit_code != 0
    assert "Traceback" not in res.output, res.output
