"""Two documents the kit reads about a project, and what it refuses to conclude from them.

`SECURITY-INSIGHTS.yml` is self-reported: a project says what its own posture is. The kit ingests
it as *declared* evidence and never as verified, which makes structural validation the only thing
standing between a half-written file and a report that quotes it as if it were complete. Every
missing field named here is one the summary would otherwise render as blank rather than absent.

A Scorecard export comes from a tool but arrives as a file, so it gets the same treatment: a
document whose root is not an object yields an empty bundle rather than an exception, and a file
too large or too deeply nested to read is bad input at exit 2, not an internal error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from oss_policy_kit.adapters import scorecard_json
from oss_policy_kit.adapters.scorecard_json import load_scorecard_auto, load_scorecard_json
from oss_policy_kit.application.insights_evidence import (
    INSIGHTS_SCHEMA_VERSION,
    _security_contacts,
    load_insights_evidence,
    validate_ingest_structure,
)
from oss_policy_kit.application.loader import LoadError

_VALID_INSIGHTS: dict[str, Any] = {
    "header": {"schema-version": INSIGHTS_SCHEMA_VERSION, "last-updated": "2026-08-11"},
    "project-lifecycle": {"status": "active"},
}


def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# SECURITY-INSIGHTS structure
# --------------------------------------------------------------------------- #


def test_a_complete_document_validates() -> None:
    errors, warnings = validate_ingest_structure(_VALID_INSIGHTS)

    assert errors == []
    assert warnings == []


@pytest.mark.parametrize(
    ("label", "doc", "named"),
    [
        ("no lifecycle block", {"header": _VALID_INSIGHTS["header"]}, "project-lifecycle"),
        (
            "a lifecycle block with no status",
            {"header": _VALID_INSIGHTS["header"], "project-lifecycle": {"bug-fixes-only": True}},
            "project-lifecycle.status",
        ),
        (
            "no schema version",
            {"header": {"last-updated": "2026-08-11"}, "project-lifecycle": {"status": "active"}},
            "header.schema-version",
        ),
        (
            "no last-updated",
            {"header": {"schema-version": INSIGHTS_SCHEMA_VERSION}, "project-lifecycle": {"status": "active"}},
            "header.last-updated",
        ),
    ],
)
def test_each_missing_field_is_named_rather_than_rendered_blank(label: str, doc: dict[str, Any], named: str) -> None:
    """A summary that shows an empty value reads as "declared nothing", not "field absent"."""

    errors, _warnings = validate_ingest_structure(doc)

    assert any(named in e for e in errors), label


def test_a_lifecycle_block_of_the_wrong_type_is_not_asked_for_a_status() -> None:
    """It is already reported as present; demanding a key from a string would double-report."""

    errors, _warnings = validate_ingest_structure({"header": _VALID_INSIGHTS["header"], "project-lifecycle": "active"})

    assert not any("project-lifecycle.status" in e for e in errors)


def test_a_newer_schema_version_is_a_warning_not_an_error() -> None:
    """The kit summarises what it recognises rather than refusing a document from the future."""

    errors, warnings = validate_ingest_structure(
        {"header": {"schema-version": "9.9.9", "last-updated": "2026-08-11"}, "project-lifecycle": {"status": "active"}}
    )

    assert errors == []
    assert warnings
    assert "9.9.9" in warnings[0]


# --------------------------------------------------------------------------- #
# Security contacts
# --------------------------------------------------------------------------- #


def test_contacts_are_collected_from_both_places_a_project_may_declare_them() -> None:
    doc = {
        "security-contacts": [{"type": "email", "value": "security@example.com"}],
        "vulnerability-reporting": {"email-contact": "vulns@example.com"},
    }
    assert _security_contacts(doc) == ["security@example.com", "vulns@example.com"]


def test_one_address_declared_twice_is_listed_once() -> None:
    """The list goes in a report; the same address twice reads as two channels."""

    doc = {
        "security-contacts": [{"value": "security@example.com"}, {"value": "security@example.com"}],
        "vulnerability-reporting": {"email-contact": "security@example.com"},
    }
    assert _security_contacts(doc) == ["security@example.com"]


@pytest.mark.parametrize(
    ("label", "doc"),
    [
        ("entries that are not objects", {"security-contacts": ["security@example.com", 7, None]}),
        ("a value that is not a string", {"security-contacts": [{"value": 7}]}),
        ("an empty value", {"security-contacts": [{"value": ""}]}),
        ("no contacts key at all", {}),
        ("contacts that are not a list", {"security-contacts": "security@example.com"}),
        ("reporting that is not an object", {"vulnerability-reporting": "security@example.com"}),
    ],
)
def test_a_contact_the_reader_cannot_use_is_not_invented(label: str, doc: dict[str, Any]) -> None:
    assert _security_contacts(doc) == [], label


# --------------------------------------------------------------------------- #
# Where the ingested file came from
# --------------------------------------------------------------------------- #


def test_the_source_is_recorded_relative_to_the_repository(tmp_path: Path) -> None:
    _write(tmp_path, "SECURITY-INSIGHTS.yml", yaml.safe_dump(_VALID_INSIGHTS))
    evidence = load_insights_evidence(tmp_path)

    assert evidence is not None
    assert evidence.source_rel == "SECURITY-INSIGHTS.yml"
    assert evidence.valid is True


def test_an_incomplete_document_is_ingested_but_marked_invalid(tmp_path: Path) -> None:
    """Still read -- the signals are useful -- but never quoted as a complete declaration."""

    _write(tmp_path, "SECURITY-INSIGHTS.yml", yaml.safe_dump({"header": {"schema-version": INSIGHTS_SCHEMA_VERSION}}))
    evidence = load_insights_evidence(tmp_path)

    assert evidence is not None
    assert evidence.valid is False


def test_no_insights_file_is_no_evidence(tmp_path: Path) -> None:
    assert load_insights_evidence(tmp_path) is None


# --------------------------------------------------------------------------- #
# Scorecard exports
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", ['["not", "a", "scorecard"]', '"a string"', "42", "null"])
def test_a_scorecard_export_that_is_not_an_object_yields_an_empty_bundle(body: str, tmp_path: Path) -> None:
    """Empty rather than raising: an unusable export is a repository with no Scorecard signal."""

    path = _write(tmp_path, "scorecard.json", body)
    bundle = load_scorecard_json(path)

    assert bundle.checks == []
    assert bundle.aggregate_score is None


def test_a_real_export_is_read(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "scorecard.json",
        json.dumps({"score": 7.5, "date": "2026-08-01", "checks": [{"name": "Branch-Protection", "score": 9}]}),
    )
    bundle = load_scorecard_json(path)

    assert [c.name for c in bundle.checks] == ["Branch-Protection"]
    assert bundle.aggregate_score == 7.5
    assert bundle.result_date == "2026-08-01"


def test_an_oversized_yaml_export_is_refused_before_it_is_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The YAML branch needs the same ceiling as the JSON one, for the same reason."""

    path = _write(tmp_path, "scorecard.yaml", "checks: []\n")
    monkeypatch.setattr(scorecard_json, "MAX_EVIDENCE_BYTES", 1)

    with pytest.raises(LoadError, match="Scorecard YAML"):
        load_scorecard_auto(path)


def test_a_yaml_export_within_the_ceiling_is_read(tmp_path: Path) -> None:
    path = _write(tmp_path, "scorecard.yaml", "score: 6.0\nchecks:\n  - name: Fuzzing\n    score: 10\n")
    bundle = load_scorecard_auto(path)

    assert [c.name for c in bundle.checks] == ["Fuzzing"]
