"""Reading two evaluation reports well enough to say what moved between them.

Drift compares reports an operator supplies, which means the inputs are files from whenever and
wherever -- an older contract version, a partial run, something hand-trimmed for a ticket. Both
readers here are the thin layer that has to survive that, and both have a history:
`_result_map` once read the `reports/1.0` shape that v9.0.0 removed, so every report the kit
produced indexed to an empty map and drift was silently always empty.

That is the failure mode worth naming. A reader that returns nothing does not look broken -- it
looks like a repository whose posture did not change, which is exactly the answer an operator
running drift is hoping for and least likely to question.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.application.drift import _extract_profile_id, _result_map

# --------------------------------------------------------------------------- #
# Which profile produced the report
# --------------------------------------------------------------------------- #


def test_the_current_contract_nests_the_profile_id() -> None:
    assert _extract_profile_id({"profile": {"id": "github-level-3"}}) == "github-level-3"


def test_an_older_contract_carries_it_flat() -> None:
    """reports/0.3 and 0.2 put it at the root; drift still has to read those."""

    assert _extract_profile_id({"profile_id": "github-level-2"}) == "github-level-2"


def test_the_nested_id_wins_when_a_report_carries_both() -> None:
    assert _extract_profile_id({"profile": {"id": "nested"}, "profile_id": "flat"}) == "nested"


@pytest.mark.parametrize(
    ("label", "report"),
    [
        ("nested id is blank", {"profile": {"id": "   "}, "profile_id": "flat"}),
        ("nested id is not a string", {"profile": {"id": 7}, "profile_id": "flat"}),
        ("profile block is not an object", {"profile": "github-level-3", "profile_id": "flat"}),
    ],
)
def test_an_unusable_nested_id_falls_through_to_the_flat_one(label: str, report: dict[str, Any]) -> None:
    """Falling through beats returning a blank: a blank id compares equal to another blank."""

    assert _extract_profile_id(report) == "flat", label


@pytest.mark.parametrize(
    ("label", "report"),
    [
        ("nothing at all", {}),
        ("flat id is blank", {"profile_id": "   "}),
        ("flat id is null", {"profile_id": None}),
        ("both present but empty", {"profile": {"id": ""}, "profile_id": ""}),
    ],
)
def test_a_report_with_no_usable_id_says_so(label: str, report: dict[str, Any]) -> None:
    """`None` is the honest answer; an empty string would silently compare equal to another."""

    assert _extract_profile_id(report) is None, label


@pytest.mark.parametrize("value", [7, 3.5, True])
def test_an_id_of_the_wrong_type_is_coerced_rather_than_discarded(value: object) -> None:
    """A hand-edited report can hold a number here, and it still identifies a profile.

    Discarding it would report "no profile" for a file that plainly names one; the coercion is
    deliberately last, after both string paths have been tried.
    """

    assert _extract_profile_id({"profile_id": value}) == str(value)


# --------------------------------------------------------------------------- #
# Indexing the controls
# --------------------------------------------------------------------------- #


def test_controls_are_indexed_by_id() -> None:
    report = {"controls": [{"id": "CI-PIN-008", "state": "pass"}, {"id": "GH-PROV-023", "state": "fail"}]}

    assert sorted(_result_map(report)) == ["CI-PIN-008", "GH-PROV-023"]


@pytest.mark.parametrize(
    ("label", "report"),
    [
        ("no controls key at all", {}),
        ("controls is an object", {"controls": {"CI-PIN-008": {}}}),
        ("controls is a string", {"controls": "CI-PIN-008"}),
        ("controls is null", {"controls": None}),
    ],
)
def test_a_report_without_a_controls_list_indexes_to_nothing(label: str, report: dict[str, Any]) -> None:
    """It has to be empty *and* not raise: drift runs on files it did not produce."""

    assert _result_map(report) == {}, label


def test_rows_that_are_not_objects_are_skipped_without_losing_their_neighbours() -> None:
    """One malformed row must not cost the comparison every control beside it."""

    report = {"controls": ["nope", {"id": "CI-PIN-008", "state": "pass"}, 42, None]}

    assert list(_result_map(report)) == ["CI-PIN-008"]


def test_a_row_with_no_id_is_skipped() -> None:
    """An unnamed control cannot be matched against the other report, so it is not indexed."""

    report = {"controls": [{"state": "pass"}, {"id": "   ", "state": "fail"}, {"id": "CI-PIN-008"}]}

    assert list(_result_map(report)) == ["CI-PIN-008"]


def test_a_non_string_id_is_still_indexed_under_its_text() -> None:
    assert list(_result_map({"controls": [{"id": 42}]})) == ["42"]
