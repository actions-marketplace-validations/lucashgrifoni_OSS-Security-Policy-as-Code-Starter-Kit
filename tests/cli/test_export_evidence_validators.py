"""The structural validators behind `export-evidence --validate`, on their rejection paths.

`--validate` is the flag that decides whether a Gemara / OSCAL / in-toto document is fit to
hand to an auditor. Its happy paths were covered; almost none of its *rejection* paths were,
which is the wrong half to leave untested -- a validator that never rejects is
indistinguishable from no validator at all, and the failure is silent: a malformed document
ships marked valid.

Each test feeds one specific malformation and asserts the message names the field, because
"validation failed" with no location is not actionable for whoever has to fix the document.

The aggregation tests matter for a different reason: rolling several control results into
one document-level verdict is where a `Failed` could get swallowed. The order of precedence
is asserted directly.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.cli import export_evidence as ee

# --------------------------------------------------------------------------- #
# rolling control results into one document verdict
# --------------------------------------------------------------------------- #


def test_no_results_at_all_is_unknown_not_passed() -> None:
    """An empty evaluation is not a clean bill of health."""

    assert ee._gemara_aggregate([]) == "Unknown"


def test_one_failure_outranks_any_number_of_passes() -> None:
    """A Failed that got averaged away would be the worst possible bug in this file."""

    assert ee._gemara_aggregate(["Passed"] * 50 + ["Failed"]) == "Failed"


@pytest.mark.parametrize("contaminant", [ee._GEMARA_NEEDS_REVIEW, "Unknown"])
def test_an_unresolved_result_downgrades_the_whole_document(contaminant: str) -> None:
    """ "Needs Review" has to survive aggregation; otherwise nobody reviews it."""

    assert ee._gemara_aggregate(["Passed", contaminant, "Passed"]) == ee._GEMARA_NEEDS_REVIEW


def test_failed_still_outranks_needs_review() -> None:
    assert ee._gemara_aggregate([ee._GEMARA_NEEDS_REVIEW, "Failed"]) == "Failed"


def test_passes_and_not_applicable_together_are_a_pass() -> None:
    assert ee._gemara_aggregate(["Passed", "Not Applicable", "Passed"]) == "Passed"


def test_an_unmapped_control_state_is_unknown_rather_than_assumed() -> None:
    """A state the map does not know must not silently become a pass."""

    assert ee._gemara_result({"state": "some-future-state"}) == "Unknown"
    assert ee._gemara_result({}) == "Unknown"


# --------------------------------------------------------------------------- #
# OSCAL
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("doc", [{"assessment-results": []}, {"assessment-results": "x"}, {}])
def test_oscal_assessment_results_must_be_an_object(doc: dict[str, Any]) -> None:
    errs = ee._validate_oscal(doc)

    assert errs
    assert any("assessment-results must be an object" in e for e in errs)


def test_oscal_metadata_must_be_an_object() -> None:
    errs = ee._validate_oscal({"assessment-results": {"metadata": "not-an-object"}})

    assert any("metadata must be an object" in e for e in errs)


# --------------------------------------------------------------------------- #
# in-toto
# --------------------------------------------------------------------------- #


def test_intoto_predicate_must_be_an_object() -> None:
    errs = ee._validate_intoto({"predicate": "not-an-object"})

    assert any("predicate must be an object" in e for e in errs)


# --------------------------------------------------------------------------- #
# Gemara
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("metadata", ["not-an-object", None, {"type": "SomethingElse"}])
def test_gemara_metadata_type_is_required_to_be_an_evaluation_log(metadata: Any) -> None:
    errs = ee._validate_gemara_header({"metadata": metadata})

    assert any("metadata.type must be 'EvaluationLog'" in e for e in errs)


def test_gemara_version_is_required_once_the_type_is_right() -> None:
    errs = ee._validate_gemara_header({"metadata": {"type": "EvaluationLog"}})

    assert any("gemara-version must be set" in e for e in errs)


def test_gemara_evaluations_must_be_a_non_empty_array() -> None:
    errs = ee._validate_gemara({"evaluations": []})

    assert any("evaluations must be a non-empty array" in e for e in errs)


def test_a_gemara_evaluation_needs_assessment_logs() -> None:
    problem = ee._validate_gemara_evaluation({"name": "GOV-SEC-001", "result": "Passed", "assessment-logs": []})

    assert problem is not None
    assert "assessment-logs" in problem
    assert "GOV-SEC-001" in problem


def test_a_gemara_evaluation_needs_its_requirement_to_match_its_control() -> None:
    """Gemara requires the assessment requirement id to equal the control id."""

    problem = ee._validate_gemara_evaluation(
        {
            "name": "GOV-SEC-001",
            "result": "Passed",
            "control": {"reference-id": "GOV-SEC-001"},
            "assessment-logs": [{"requirement": {"reference-id": "GOV-SEC-999"}}],
        }
    )

    assert problem is not None
    assert "reference-id must match" in problem


def test_a_well_formed_gemara_evaluation_reports_no_problem() -> None:
    """The rejections above only mean something if the accepted shape is still accepted."""

    problem = ee._validate_gemara_evaluation(
        {
            "name": "GOV-SEC-001",
            "result": "Passed",
            "control": {"reference-id": "GOV-SEC-001"},
            "assessment-logs": [{"requirement": {"reference-id": "GOV-SEC-001"}}],
        }
    )

    assert problem is None


def test_a_non_object_evaluation_entry_is_skipped_not_fatal() -> None:
    """One malformed entry in the array must not cost the caller the whole document."""

    errs = ee._validate_gemara(
        {
            "metadata": {"type": "EvaluationLog", "gemara-version": "0.1"},
            "target": {},
            "result": "Passed",
            "evaluations": [
                "not-an-object",
                {
                    "name": "GOV-SEC-001",
                    "result": "Passed",
                    "control": {"reference-id": "GOV-SEC-001"},
                    "assessment-logs": [{"requirement": {"reference-id": "GOV-SEC-001"}}],
                },
            ],
        }
    )

    assert errs == []


@pytest.mark.parametrize(
    "container",
    ["not-a-dict", None, 42, {"control": "not-a-dict"}, {"control": None}, {}],
)
def test_reference_id_answers_none_for_any_shape_it_cannot_walk(container: Any) -> None:
    """Evidence documents come from outside; a malformed one must answer, not raise."""

    assert ee._reference_id(container, "control") is None


# --------------------------------------------------------------------------- #
# SARIF passthrough
# --------------------------------------------------------------------------- #


def test_a_rule_id_is_read_from_either_spelling() -> None:
    assert ee._result_rule_id({"ruleId": " SAST-001 "}) == "SAST-001"
    assert ee._result_rule_id({"rule": {"id": " SAST-002 "}}) == "SAST-002"


@pytest.mark.parametrize("result", [{}, {"ruleId": "   "}, {"rule": {}}, {"rule": "not-a-dict"}, {"ruleId": 42}])
def test_a_result_with_no_usable_rule_id_yields_the_empty_string(result: dict[str, Any]) -> None:
    """Returning None here would make the membership test below raise instead of skip."""

    assert ee._result_rule_id(result) == ""


def test_a_run_whose_results_are_not_a_list_passes_through_untouched() -> None:
    """Filtering needs a list; a malformed container is forwarded rather than dropped.

    Dropping it would silently remove a scanner's whole drop from the exported bundle,
    which is worse than exporting it unfiltered and visibly odd.
    """

    malformed = {"tool": {"driver": {"name": "zizmor"}}, "results": "not-a-list"}

    kept = ee._filter_passthrough_runs([malformed, "not-a-dict"], {"controls": []})

    assert kept == [malformed]


# --------------------------------------------------------------------------- #
# version resolution
# --------------------------------------------------------------------------- #


def test_the_reports_own_version_wins() -> None:
    assert ee._kit_version({"kit_version": " 9.9.9 "}) == "9.9.9"


@pytest.mark.parametrize("report", [{}, {"kit_version": ""}, {"kit_version": "   "}, {"kit_version": 10}])
def test_a_report_without_a_usable_version_falls_back_to_the_installed_one(report: dict[str, Any]) -> None:
    """An exported bundle always states a version; blank would break the consumer's schema."""

    from oss_policy_kit import __version__

    assert ee._kit_version(report) == __version__
