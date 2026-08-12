"""Every source `correlate-findings` reads keeps a record of what happened to it.

The artifact this pipeline produces is a prioritised list, and a prioritised list is read as
complete. That makes an unread source the dangerous case: a scanner whose evidence was missing,
oversized, unreadable or malformed contributes zero findings, and zero findings looks exactly
like a clean scan unless the source record says otherwise.

So each status below is asserted as a distinct value rather than lumped into "no findings":
`missing` and `unreadable` are different problems with different fixes, and `error` on a
malformed findings container is what separates "the scanner found nothing" from "the file said
something the reader could not use".

None of these paths may raise. `correlate-findings` documents that an unreadable source never
stops the run, and the two shapes that reach for `RecursionError` -- deeply nested JSON, and
CPython's integer-conversion limit -- are the ones that used to escape as exit 3.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.finding_normalization import _str_tuple, normalize_kit_evidence
from oss_policy_kit.application.finding_sarif import _project_runs
from oss_policy_kit.application.findings_report import _load_enrichment

_SEMGREP = ".oss-policy-kit/evidence/sast-semgrep.json"


def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _record_for(root: Path, filename: str) -> Any:
    _findings, records = normalize_kit_evidence(root)
    return next(r for r in records if r.path.endswith(filename))


# --------------------------------------------------------------------------- #
# Kit evidence sources
# --------------------------------------------------------------------------- #


def test_a_source_that_was_never_produced_is_recorded_as_missing(tmp_path: Path) -> None:
    assert _record_for(tmp_path, "sast-semgrep.json").status == "missing"


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("not json at all", "{ not json"),
        ("a list at the root", '["findings"]'),
        ("a bare string", '"nothing here"'),
        ("null", "null"),
        ("nested past the parser limit", "[" * 2000 + "]" * 2000),
    ],
)
def test_a_source_the_reader_cannot_use_is_recorded_as_unreadable(label: str, body: str, tmp_path: Path) -> None:
    """Including the deep-nesting case: `json.loads` raises RecursionError, not a decode error."""

    _write(tmp_path, _SEMGREP, body)
    assert _record_for(tmp_path, "sast-semgrep.json").status == "unreadable", label


@pytest.mark.parametrize("container", ['"two"', "42", "null", '{"high": 2}'])
def test_a_findings_container_of_the_wrong_type_demotes_the_source_to_error(container: str, tmp_path: Path) -> None:
    """Present but unusable is not the same as absent, and a consumer has to be able to tell."""

    _write(tmp_path, _SEMGREP, f'{{"tool": "semgrep", "status": "ok", "findings": {container}}}')
    assert _record_for(tmp_path, "sast-semgrep.json").status == "error"


def test_a_payload_with_no_findings_key_keeps_the_status_the_scanner_reported(tmp_path: Path) -> None:
    """The counterpart: nothing was malformed, so nothing is demoted."""

    _write(tmp_path, _SEMGREP, '{"tool": "semgrep", "status": "ok"}')
    assert _record_for(tmp_path, "sast-semgrep.json").status == "ok"


def test_a_genuinely_empty_findings_list_stays_ok(tmp_path: Path) -> None:
    _write(tmp_path, _SEMGREP, '{"tool": "semgrep", "status": "ok", "findings": []}')
    assert _record_for(tmp_path, "sast-semgrep.json").status == "ok"


def test_entries_that_are_not_objects_are_skipped_without_losing_their_neighbours(tmp_path: Path) -> None:
    _write(
        tmp_path,
        _SEMGREP,
        json.dumps(
            {
                "tool": "semgrep",
                "status": "ok",
                "findings": ["nope", 42, None, {"rule_id": "R1", "severity": "ERROR", "message": "m"}],
            }
        ),
    )
    findings, _records = normalize_kit_evidence(tmp_path)

    assert [f.rule for f in findings] == ["R1"]


def test_a_scanner_that_reported_a_failure_still_contributes_what_it_saw(tmp_path: Path) -> None:
    """A timed-out scan may carry partial findings; dropping them would lose real observations."""

    _write(
        tmp_path,
        _SEMGREP,
        json.dumps(
            {
                "tool": "semgrep",
                "status": "timeout",
                "findings": [{"rule_id": "R1", "severity": "ERROR", "message": "m"}],
            }
        ),
    )
    findings, _records = normalize_kit_evidence(tmp_path)

    assert [f.rule for f in findings] == ["R1"]
    assert _record_for(tmp_path, "sast-semgrep.json").status == "timeout"


@pytest.mark.parametrize(
    ("label", "value", "expected"),
    [
        ("a list of strings", ["CWE-79", "CWE-89"], ("CWE-79", "CWE-89")),
        ("blanks dropped", ["CWE-79", "  ", ""], ("CWE-79",)),
        ("non-strings dropped", ["CWE-79", 7, None], ("CWE-79",)),
        ("not a list at all", "CWE-79", ()),
        ("a mapping", {"cwe": "CWE-79"}, ()),
        ("absent", None, ()),
    ],
)
def test_a_string_list_field_only_yields_real_strings(label: str, value: Any, expected: tuple[str, ...]) -> None:
    """These feed `cwe` and `owasp` tags; a stray `None` would render as the text "None"."""

    assert _str_tuple(value) == expected, label


# --------------------------------------------------------------------------- #
# SARIF runs
# --------------------------------------------------------------------------- #


def test_runs_that_are_not_objects_are_walked_past() -> None:
    runs = ["nope", 42, None, {"tool": {"driver": {"name": "semgrep", "version": "1.2.3"}}, "results": []}]
    projection = _project_runs(runs, "semgrep", "sast.sarif")

    assert projection.tool_version == "1.2.3"
    assert projection.container_invalid is False


def test_a_results_key_of_the_wrong_type_marks_the_container_invalid() -> None:
    """Zero findings from an unreadable container must not read as a clean scan."""

    runs = [{"tool": {"driver": {"name": "semgrep"}}, "results": "two"}]
    assert _project_runs(runs, "semgrep", "sast.sarif").container_invalid is True


def test_a_run_with_no_results_key_is_not_marked_invalid() -> None:
    """The counterpart: a run that declares nothing is not a run that declared nonsense."""

    runs = [{"tool": {"driver": {"name": "semgrep"}}}]
    assert _project_runs(runs, "semgrep", "sast.sarif").container_invalid is False


def test_the_first_declared_version_wins_over_a_later_silent_run() -> None:
    """Versions are read once; a second run without one must not blank the first."""

    runs = [
        {"tool": {"driver": {"name": "semgrep", "version": "1.2.3"}}, "results": []},
        {"tool": {"driver": {"name": "semgrep"}}, "results": []},
    ]
    assert _project_runs(runs, "semgrep", "sast.sarif").tool_version == "1.2.3"


def test_a_document_produced_by_another_tool_is_attributed_to_that_tool() -> None:
    """The slot filename is not evidence of authorship; the driver name is."""

    runs = [{"tool": {"driver": {"name": "trivy", "version": "0.50"}}, "results": []}]
    assert _project_runs(runs, "semgrep", "sast.sarif").foreign_driver == "trivy"


# --------------------------------------------------------------------------- #
# The offline enrichment snapshot
# --------------------------------------------------------------------------- #


def test_an_enrichment_snapshot_that_is_not_there_is_recorded_as_missing(tmp_path: Path) -> None:
    _table, record = _load_enrichment(tmp_path / "enrichment.json")

    assert record.status == "missing"
    assert record.path == "enrichment.json", "the basename only: the auditor's path is not evidence"


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("not json", "{ not json"),
        ("a list at the root", "[]"),
        ("a bare number", "42"),
        ("nested past the parser limit", "[" * 2000 + "]" * 2000),
    ],
)
def test_an_enrichment_snapshot_the_reader_cannot_use_is_recorded_as_unreadable(
    label: str, body: str, tmp_path: Path
) -> None:
    path = _write(tmp_path, "enrichment.json", body)
    table, record = _load_enrichment(path)

    assert record.status == "unreadable", label
    assert table == {}


def test_an_oversized_snapshot_is_refused_before_it_is_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ceiling exists so a hostile file never reaches the JSON parser at all."""

    from oss_policy_kit.application import findings_report

    path = _write(tmp_path, "enrichment.json", "{}")
    monkeypatch.setattr(findings_report, "MAX_EVIDENCE_BYTES", 1)
    _table, record = _load_enrichment(path)

    assert record.status == "oversize"


def test_a_usable_snapshot_carries_its_as_of_date_and_its_inferred_trust_label(tmp_path: Path) -> None:
    """The label is the point: this data is user-supplied and must never look authoritative."""

    path = _write(
        tmp_path,
        "enrichment.json",
        json.dumps({"as_of": "2026-08-01", "vulnerabilities": {"CVE-2026-1": {"epss": 0.4, "kev": True}}}),
    )
    table, record = _load_enrichment(path)

    assert table["CVE-2026-1"]["kev"] is True
    assert record.status == "ok"
    assert record.tool_version == "2026-08-01"
    assert "inferred trust" in record.tool


def test_entries_that_are_not_objects_are_dropped_from_the_snapshot(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "enrichment.json",
        json.dumps({"vulnerabilities": {"CVE-2026-1": "high", "CVE-2026-2": {"epss": 0.1}}}),
    )
    table, _record = _load_enrichment(path)

    assert list(table) == ["CVE-2026-2"]


def test_a_snapshot_with_no_vulnerabilities_block_is_still_usable(tmp_path: Path) -> None:
    """It is empty, not broken; recording it as unreadable would misdescribe the file."""

    path = _write(tmp_path, "enrichment.json", json.dumps({"as_of": "2026-08-01"}))
    table, record = _load_enrichment(path)

    assert table == {}
    assert record.status == "ok"
