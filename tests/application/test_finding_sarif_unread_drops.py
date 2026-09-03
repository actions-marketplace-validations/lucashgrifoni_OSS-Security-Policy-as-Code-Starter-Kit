"""A corrupt scanner drop is recorded as unread, never raised, and never scored.

`correlate-findings` reads SARIF written by four other tools. Any of those files can be
truncated, BOM-prefixed, wrongly encoded, or not SARIF at all, and none of that may end the
run: the contract is that a bad drop becomes a *reported* unread source, so the operator can
see the correlation was partial rather than believing four scanners found nothing.

Every failure path in the reader returns its reason instead of raising. Those returns had
not been executed, and neither had the numeric sanitiser that keeps a garbage EPSS or CVSS
out of the ranking.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import finding_sarif as fs


def _write(tmp_path: Path, body: str, *, name: str = "scan.sarif", encoding: str = "utf-8") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding=encoding)
    return path


_VALID = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": []}]}


# --------------------------------------------------------------------------- #
# files that can be read
# --------------------------------------------------------------------------- #


def test_a_well_formed_drop_yields_its_runs(tmp_path: Path) -> None:
    runs, error = fs._load_runs(_write(tmp_path, json.dumps(_VALID)))

    assert error is None
    assert isinstance(runs, list)
    assert len(runs) == 1


def test_a_bom_prefixed_file_is_read_rather_than_rejected(tmp_path: Path) -> None:
    """Most Windows tools write a BOM; treating it as corruption would drop real findings."""

    path = _write(tmp_path, json.dumps(_VALID), encoding="utf-8-sig")

    runs, error = fs._load_runs(path)

    assert error is None
    assert runs is not None


def test_a_document_declaring_the_canonical_sarif_schema_without_runs_is_accepted(tmp_path: Path) -> None:
    """A scanner that found nothing may omit `runs` entirely while naming the schema."""

    doc = {"$schema": ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json")}

    runs, error = fs._load_runs(_write(tmp_path, json.dumps(doc)))

    assert error is None
    assert runs == []


def test_the_schema_allowance_is_narrow_and_stays_narrow(tmp_path: Path) -> None:
    """Only the canonical OASIS filename waives the `runs` requirement.

    Pinning the current behaviour rather than widening it: the schemastore mirror spells the
    file `sarif-2.1.0.json`, so a document using that URL *and* omitting `runs` is reported
    as unread. That is a visible, reported outcome rather than a silent drop, so widening
    the match would need evidence that a real scanner emits this combination.
    """

    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json"}

    runs, error = fs._load_runs(_write(tmp_path, json.dumps(doc)))

    assert runs is None
    assert error == "SARIF file missing top-level 'runs' array."


def test_that_same_mirror_url_is_fine_as_long_as_runs_is_present(tmp_path: Path) -> None:
    """The allowance only ever mattered for documents with no `runs` at all."""

    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []}

    runs, error = fs._load_runs(_write(tmp_path, json.dumps(doc)))

    assert error is None
    assert runs == []


# --------------------------------------------------------------------------- #
# files that cannot -- each returns its reason
# --------------------------------------------------------------------------- #


def test_a_file_that_cannot_be_opened_is_reported_not_raised(tmp_path: Path) -> None:
    """A directory where a drop was expected is the shape this takes on a real run."""

    path = tmp_path / "scan.sarif"
    path.mkdir()

    runs, error = fs._load_runs(path)

    assert runs is None
    assert error is not None
    assert "Could not read SARIF file" in error


def test_bytes_that_are_not_utf8_are_reported(tmp_path: Path) -> None:
    """A drop written in a legacy codepage must not end the correlation."""

    path = tmp_path / "scan.sarif"
    path.write_bytes(b'{"runs": [] , "note": "\xff\xfe not utf-8"}')

    runs, error = fs._load_runs(path)

    assert runs is None
    assert error is not None
    assert "decode" in error.lower()


def test_unparseable_json_is_reported_with_the_parser_message(tmp_path: Path) -> None:
    runs, error = fs._load_runs(_write(tmp_path, '{"runs": ['))

    assert runs is None
    assert error is not None
    assert "Could not parse SARIF JSON" in error


def test_a_document_nested_past_the_depth_guard_is_reported(tmp_path: Path) -> None:
    """The guard is shared with the evaluate path so the two cannot drift apart."""

    depth = fs._MAX_SARIF_JSON_DEPTH + 5
    runs, error = fs._load_runs(_write(tmp_path, "[" * depth + "]" * depth))

    assert runs is None
    assert error is not None
    assert "too deeply nested" in error


@pytest.mark.parametrize("body", ["[]", '"a string"', "42", "null"])
def test_a_root_that_is_not_an_object_is_reported_as_missing_runs(tmp_path: Path, body: str) -> None:
    runs, error = fs._load_runs(_write(tmp_path, body))

    assert runs is None
    assert error == "SARIF file missing top-level 'runs' array."


def test_an_object_with_neither_runs_nor_the_schema_is_reported(tmp_path: Path) -> None:
    """This is what pointing the command at the wrong JSON file looks like."""

    runs, error = fs._load_runs(_write(tmp_path, json.dumps({"findings": []})))

    assert runs is None
    assert error == "SARIF file missing top-level 'runs' array."


def test_a_non_string_schema_field_does_not_crash_the_reader(tmp_path: Path) -> None:
    """`str()` before `endswith` -- a malformed `$schema` is bad input, not a crash."""

    runs, error = fs._load_runs(_write(tmp_path, json.dumps({"$schema": 42})))

    assert runs is None
    assert error == "SARIF file missing top-level 'runs' array."


def test_runs_that_are_not_an_array_are_reported(tmp_path: Path) -> None:
    runs, error = fs._load_runs(_write(tmp_path, json.dumps({"runs": {"0": {}}})))

    assert runs is None
    assert error == "SARIF 'runs' is not an array."


# --------------------------------------------------------------------------- #
# numbers that must not warp the ranking
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw", [0.42, "0.42", 1, "1"])
def test_a_usable_number_is_accepted(raw: Any) -> None:
    assert fs._safe_float(raw, lo=0.0, hi=1.0) is not None


@pytest.mark.parametrize("raw", [None, "not-a-number", {}, [], object()])
def test_a_value_that_is_not_a_number_is_dropped(raw: Any) -> None:
    """EPSS and CVSS arrive from third-party enrichment; garbage must not reach the rank."""

    assert fs._safe_float(raw, lo=0.0, hi=1.0) is None


@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", float("nan"), float("inf")])
def test_a_non_finite_number_is_dropped(raw: Any) -> None:
    """`float("nan")` parses fine and would poison every comparison it takes part in."""

    assert fs._safe_float(raw, lo=0.0, hi=1.0) is None


@pytest.mark.parametrize("raw", [-0.1, 1.1, 99])
def test_a_number_outside_the_declared_range_is_dropped(raw: float) -> None:
    """An EPSS above 1.0 is not a very likely exploit; it is a broken feed."""

    assert fs._safe_float(raw, lo=0.0, hi=1.0) is None


def test_the_bounds_are_inclusive() -> None:
    assert fs._safe_float(0.0, lo=0.0, hi=1.0) == 0.0
    assert fs._safe_float(1.0, lo=0.0, hi=1.0) == 1.0


def test_without_bounds_any_finite_number_is_kept() -> None:
    assert fs._safe_float(-5.0) == -5.0


# --------------------------------------------------------------------------- #
# locations that a scanner may not provide
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "result"),
    [
        ("no locations key", {}),
        ("locations is not a list", {"locations": "src/app.py"}),
        ("an empty locations list", {"locations": []}),
        ("the first location is not an object", {"locations": ["src/app.py"]}),
        ("no physicalLocation", {"locations": [{}]}),
        ("physicalLocation is not an object", {"locations": [{"physicalLocation": "src/app.py"}]}),
    ],
)
def test_a_result_without_a_usable_location_yields_an_empty_one(label: str, result: dict[str, Any]) -> None:
    """A finding with no file is still a finding; it must not be dropped or crash the merge."""

    location = fs._location(result)

    assert location.file in (None, "")


def test_a_usable_location_is_read() -> None:
    """The negative cases above only mean something if a real location still parses."""

    result = {
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 12},
                }
            }
        ]
    }

    location = fs._location(result)

    assert location.file == "src/app.py"
    assert location.line_start == 12
