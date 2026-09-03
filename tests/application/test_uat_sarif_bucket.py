"""UAT regressions for the external-SARIF normalizer (finding_sarif).

Each test pins one confirmed defect from the clean-room campaign, stated as the
consequence an auditor would live with:

- bom              a UTF-8 BOM (what most Windows tools write by default) made
                   every finding in the drop disappear while ``--fail-on-severity``
                   stayed green, and a non-string ``$schema`` crashed the command
                   with exit 3 instead of being reported as unread
- sarif-driver     a document produced by another scanner was attributed to the
                   tool the FILENAME implies, so the artifact asserted that
                   gitleaks ran on output gitleaks never produced
- sarif-kind-pass  results explicitly marked ``kind: "pass"`` / ``"notApplicable"``
                   were counted as findings, turning a clean scan into a FAIL
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from oss_policy_kit.application.finding_sarif import normalize_sarif_sources
from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()

_SAST = Path(".oss-policy-kit") / "evidence" / "sast"


def _result(rule: str, *, level: str = "error", kind: str | None = None) -> dict[str, Any]:
    r: dict[str, Any] = {"ruleId": rule, "level": level, "message": {"text": "msg"}}
    if kind is not None:
        r["kind"] = kind
    return r


def _sarif(driver: str, results: list[dict[str, Any]], *, version: str = "1.0.0") -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": driver, "version": version}}, "results": results}],
    }


def _write(repo: Path, filename: str, payload: object, *, encoding: str = "utf-8") -> None:
    path = repo / _SAST / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(text, encoding=encoding)


# --------------------------------------------------------------------------- #
# bom
# --------------------------------------------------------------------------- #


def test_bom_prefixed_drop_still_reports_its_findings(tmp_path: Path) -> None:
    """A leaked secret must not vanish because the scanner wrote UTF-8 with a BOM."""

    _write(
        tmp_path,
        "gitleaks.sarif.json",
        _sarif("gitleaks", [_result("generic-api-key")]),
        encoding="utf-8-sig",
    )
    findings, records = normalize_sarif_sources(tmp_path)
    assert [f.rule for f in findings] == ["generic-api-key"]
    assert next(r for r in records if r.tool == "gitleaks").status == "ok"


def test_bom_prefixed_drop_still_trips_the_severity_gate(tmp_path: Path) -> None:
    """The BOM must not turn a blocking --fail-on-severity run green."""

    _write(
        tmp_path,
        "gitleaks.sarif.json",
        _sarif("gitleaks", [_result("generic-api-key")]),
        encoding="utf-8-sig",
    )
    result = runner.invoke(
        app,
        prepare_cli_args(["correlate-findings", "--target", str(tmp_path), "--fail-on-severity", "high"]),
    )
    assert result.exit_code == 1


def test_malformed_drops_are_recorded_never_crash_the_run(tmp_path: Path) -> None:
    """Corrupt evidence must degrade to an honest record, not an exit-3 traceback."""

    # Each shape reached an unguarded .get()/.endswith() on a non-object value.
    _write(tmp_path, "poutine.sarif.json", '{"$schema": 123, "runs": [{"tool": "x", "results": []}]}')
    _write(
        tmp_path,
        "zizmor.sarif.json",
        {"runs": [{"tool": {"driver": "x"}, "results": [_result("R1")]}]},
    )
    _write(tmp_path, "gitleaks.sarif.json", "not json at all")
    findings, records = normalize_sarif_sources(tmp_path)
    by_tool = {r.tool: r.status for r in records}
    assert by_tool["gitleaks"] == "unreadable"
    assert by_tool["poutine"] == "ok"  # genuinely empty, just oddly typed metadata
    assert [f.rule for f in findings] == ["R1"]


# --------------------------------------------------------------------------- #
# sarif-driver
# --------------------------------------------------------------------------- #


def test_foreign_scanner_output_is_not_attributed_to_the_filename_tool(tmp_path: Path) -> None:
    """A Trivy report in gitleaks.sarif.json must never let anything claim gitleaks ran."""

    _write(
        tmp_path,
        "gitleaks.sarif.json",
        _sarif("Trivy", [_result("CVE-2026-9999")], version="0.50.0"),
    )
    findings, records = normalize_sarif_sources(tmp_path)
    record = next(r for r in records if r.tool == "gitleaks")
    assert record.status == "error"
    assert record.tool_version is None  # never assert a version for a tool that did not run
    assert {s.tool for f in findings for s in f.sources} == {"Trivy"}
    assert all(t != "gitleaks" for f in findings for t, _ in f.severity.by_source)


def test_expected_and_unrecognized_driver_names_keep_slot_attribution(tmp_path: Path) -> None:
    """Only a positively identified foreign scanner may override the slot; nothing else."""

    _write(tmp_path, "gitleaks.sarif.json", _sarif("gitleaks", [_result("generic-api-key")]))
    # A generic or vendor-custom driver name proves nothing, so the drop stays the slot's.
    _write(tmp_path, "poutine.sarif.json", _sarif("in-house-wrapper", [_result("R1")]))
    findings, records = normalize_sarif_sources(tmp_path)
    by_tool = {r.tool: r.status for r in records}
    assert by_tool["gitleaks"] == "ok"
    assert by_tool["poutine"] == "ok"
    assert {s.tool for f in findings for s in f.sources} == {"gitleaks", "poutine"}


# --------------------------------------------------------------------------- #
# sarif-kind-pass
# --------------------------------------------------------------------------- #


def test_passing_and_not_applicable_results_are_not_findings(tmp_path: Path) -> None:
    """A scanner that reports its passing rules must not be read as a wall of findings."""

    _write(
        tmp_path,
        "zizmor.sarif.json",
        _sarif(
            "zizmor",
            [
                _result("R-PASS", kind="pass"),
                _result("R-NA", kind="notApplicable"),
                _result("R-REVIEW", kind="review"),  # undecided: still a finding
                _result("R-REAL", kind="fail"),
                _result("R-DEFAULT"),  # no kind -> SARIF default "fail"
            ],
        ),
    )
    findings, records = normalize_sarif_sources(tmp_path)
    assert [f.rule for f in findings] == ["R-REVIEW", "R-REAL", "R-DEFAULT"]
    assert next(r for r in records if r.tool == "zizmor").status == "ok"


def test_all_passing_scan_does_not_trip_the_severity_gate(tmp_path: Path) -> None:
    """A clean scan must exit 0, even when the tool stamps level=error on its passes."""

    _write(
        tmp_path,
        "zizmor.sarif.json",
        _sarif("zizmor", [_result("R-PASS", kind="pass"), _result("R-NA", kind="notApplicable")]),
    )
    result = runner.invoke(
        app,
        prepare_cli_args(["correlate-findings", "--target", str(tmp_path), "--fail-on-severity", "high"]),
    )
    assert result.exit_code == 0
