"""The structural messages `emit-vex` gives back when the SARIF it was handed is malformed.

These exist so an operator who points `emit-vex` at the wrong file, or at a truncated scan,
gets a sentence naming the field and what was there instead -- rather than a stack trace, or
worse, a VEX document built from a file that was never read properly.

Two of the guards matter beyond message quality. `results: null` must be reported rather
than read as "this run found nothing": a scan whose results array failed to serialise would
otherwise produce a VEX asserting zero vulnerabilities. And the producer-name probe is what
lets the command refuse a SARIF that is not a vulnerability scan at all.

Both had branches nothing executed.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.cli import emit_vex as ev

# --------------------------------------------------------------------------- #
# naming what was actually there
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "a boolean"),
        (False, "a boolean"),
        (None, "null"),
        (1, "a number"),
        (1.5, "a number"),
        ("x", "a string"),
        ([], "an array"),
        ({}, "an object"),
    ],
)
def test_a_json_value_is_named_the_way_the_sarif_author_would_recognise_it(value: Any, expected: str) -> None:
    """`True` is an `int` subclass in Python; reporting a boolean as "a number" would send
    the reader looking for the wrong thing."""

    assert ev._json_type_name(value) == expected


# --------------------------------------------------------------------------- #
# tool / driver / rules
# --------------------------------------------------------------------------- #


def test_a_run_with_no_tool_section_produces_no_structural_complaint() -> None:
    """`tool` is optional at this layer; absence is not malformation."""

    assert ev._validate_sarif_tool(0, {}, 10) == []


@pytest.mark.parametrize(
    ("run", "fragment"),
    [
        ({"tool": "semgrep"}, "runs[0].tool must be an object, not a string"),
        ({"tool": {"driver": []}}, "runs[0].tool.driver must be an object, not an array"),
        ({"tool": {"driver": {"rules": "none"}}}, "runs[0].tool.driver.rules must be an array, not a string"),
    ],
)
def test_a_malformed_tool_section_names_the_field_and_the_type_found(run: dict[str, Any], fragment: str) -> None:
    errs = ev._validate_sarif_tool(0, run, 10)

    assert errs == [fragment]


def test_a_driver_without_rules_is_accepted() -> None:
    assert ev._validate_sarif_tool(0, {"tool": {"driver": {"name": "semgrep"}}}, 10) == []


# --------------------------------------------------------------------------- #
# results
# --------------------------------------------------------------------------- #


def test_a_run_that_is_not_an_object_is_reported() -> None:
    assert ev._validate_sarif_run(0, "semgrep", 10) == ["runs[0] must be an object, not a string"]


def test_a_run_with_no_results_key_is_accepted() -> None:
    """A run that never declares results is honestly empty, not malformed."""

    assert ev._validate_sarif_run(0, {"tool": {"driver": {"name": "x"}}}, 10) == []


@pytest.mark.parametrize(
    ("results", "expected_type"),
    [(None, "null"), ("none", "a string"), ({}, "an object"), (0, "a number")],
)
def test_results_that_are_not_an_array_are_reported_rather_than_read_as_empty(results: Any, expected_type: str) -> None:
    """`results: null` is the case worth naming.

    Reading it as "this run found nothing" would let a scan whose results failed to
    serialise produce a VEX document asserting zero vulnerabilities.
    """

    errs = ev._validate_sarif_run(0, {"results": results}, 10)

    assert errs == [f"runs[0].results must be an array, not {expected_type}"]


def test_an_empty_results_array_is_accepted() -> None:
    """The honest empty scan, which must stay distinguishable from the case above."""

    assert ev._validate_sarif_run(0, {"results": []}, 10) == []


def test_tool_and_results_problems_are_both_reported() -> None:
    errs = ev._validate_sarif_run(0, {"tool": "semgrep", "results": None}, 10)

    assert len(errs) == 2


# --------------------------------------------------------------------------- #
# which scanner produced the document
# --------------------------------------------------------------------------- #


def test_the_producer_name_is_read_from_the_first_run_that_declares_one() -> None:
    doc = {"runs": [{"tool": {"driver": {"name": "  osv-scanner  "}}}]}

    assert ev._sarif_producer_name(doc) == "osv-scanner"


def test_a_later_run_supplies_the_name_when_earlier_ones_do_not() -> None:
    """Aggregated SARIF puts several runs in one file; the first usable name wins."""

    doc = {
        "runs": [
            "not-a-run",
            {"tool": "not-an-object"},
            {"tool": {"driver": "not-an-object"}},
            {"tool": {"driver": {"name": ""}}},
            {"tool": {"driver": {"name": "trivy"}}},
        ]
    }

    assert ev._sarif_producer_name(doc) == "trivy"


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"runs": "not-a-list"},
        {"runs": []},
        {"runs": [{}]},
        {"runs": [{"tool": {"driver": {"name": "   "}}}]},
        {"runs": [{"tool": {"driver": {"name": 42}}}]},
    ],
)
def test_a_document_that_never_names_its_producer_yields_none(doc: dict[str, Any]) -> None:
    """None is what the caller checks before refusing a non-vulnerability SARIF."""

    assert ev._sarif_producer_name(doc) is None


# --------------------------------------------------------------------------- #
# the error budget
# --------------------------------------------------------------------------- #


def test_the_message_list_is_capped_so_a_broken_file_does_not_flood_the_terminal() -> None:
    """A wholly malformed scan would otherwise print one line per element."""

    doc = {"runs": [{"results": ["not-an-object"] * 200}]}

    errs = ev._validate_sarif_structure(doc)

    assert 0 < len(errs) <= ev._MAX_SARIF_STRUCTURE_ERRORS


def test_a_well_formed_document_produces_no_messages() -> None:
    """The cap and the guards only mean something if a real SARIF still passes clean."""

    doc = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "osv-scanner", "rules": []}}, "results": []}],
    }

    assert ev._validate_sarif_structure(doc) == []
