"""How a control result becomes a trust level, and what it may never become.

This projection is the part of the report a reader uses to decide how much a control's verdict
is worth. Its whole job is refusing to inflate: a heuristic signal is `inferred` however
confident the evaluator sounded, a static clone read is `declared` and not `verified`, and only
a fresh, attested API collection earns `verified`. Getting any of those one step too generous
makes a repository look better attested than it is, which is the failure this module exists to
prevent -- and it was the least tested part of it.

The source-platform and digest helpers are here for the same reason: they read `result.extra`,
which is free-form, so a string where a mapping was expected must yield "unknown" rather than
raising or being coerced into a claim.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.application.evidence_projection import (
    FreshnessContext,
    _digest_and_schema_from_result,
    _source_platform_from_result,
    _trust_level,
    project_evidence,
)
from oss_policy_kit.domain.models import ControlResult, ControlStatus


def _result(
    *,
    control_id: str = "GOV-SEC-001",
    status: ControlStatus = ControlStatus.PASS,
    extra: Any = None,
    method: str | None = None,
    sources: list[str] | None = None,
) -> ControlResult:
    kwargs: dict[str, Any] = {
        "control_id": control_id,
        "title": "t",
        "category": "governance",
        "status": status,
        "profile": "p",
        "evidence_sources": sources or [],
        "confidence": "high",
        "reason": "r",
        "remediation": "rem",
    }
    result = ControlResult(**kwargs)
    if extra is not None:
        object.__setattr__(result, "extra", extra)
    if method is not None:
        object.__setattr__(result, "evidence_collection_method", method)
    return result


# --------------------------------------------------------------------------- #
# trust_level
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (ControlStatus.NOT_OBSERVABLE, "unobserved"),
        (ControlStatus.NOT_APPLICABLE, "unobserved"),
        (ControlStatus.NOT_EVALUATED, "unobserved"),
        (ControlStatus.MANUAL_REVIEW_REQUIRED, "inferred"),
    ],
)
def test_a_status_that_asserts_nothing_cannot_reach_a_high_trust_level(status: ControlStatus, expected: str) -> None:
    """The status wins over the source: an unobserved control is unobserved however collected."""

    level = _trust_level(
        result=_result(status=status), source_type="api_collected", freshness="fresh", attestation="signed"
    )
    assert level == expected


@pytest.mark.parametrize(
    ("source_type", "expected"),
    [
        ("heuristic_signal", "inferred"),
        ("static_clone", "declared"),
        ("user_supplied", "declared"),
        ("derived", "inferred"),
        ("something_new", "unobserved"),
    ],
)
def test_each_source_type_has_its_own_ceiling(source_type: str, expected: str) -> None:
    """A source the projection does not recognise must fall to the floor, not the top."""

    level = _trust_level(result=_result(), source_type=source_type, freshness="fresh", attestation="signed")
    assert level == expected


def test_only_a_fresh_attested_collection_is_verified() -> None:
    assert (
        _trust_level(result=_result(), source_type="api_collected", freshness="fresh", attestation="signed")
        == "verified"
    )


@pytest.mark.parametrize(
    ("freshness", "attestation"),
    [
        ("stale", "signed"),
        ("fresh", "none"),
        ("unknown", "signed"),
        ("stale", "none"),
    ],
)
def test_anything_less_than_fresh_and_attested_is_only_declared(freshness: str, attestation: str) -> None:
    """Stale, unattested, and freshness-unknown all land on the same rung, by design."""

    level = _trust_level(result=_result(), source_type="api_collected", freshness=freshness, attestation=attestation)
    assert level == "declared"


# --------------------------------------------------------------------------- #
# Reading the free-form `extra`
# --------------------------------------------------------------------------- #


def test_an_explicit_source_platform_wins_over_the_control_id_heuristic() -> None:
    result = _result(control_id="AZ-PLAT-034", extra={"source_platform": "gitlab"})
    assert _source_platform_from_result(result) == "gitlab"


@pytest.mark.parametrize(
    ("control_id", "expected"),
    [
        ("AZ-PLAT-034", "azure"),
        ("AWS-CB-045", "aws"),
        ("GH-PLAT-024", "github"),
        ("PLAT-BRPROT-015", "github"),
        ("GOV-SEC-001", "local"),
        ("XX-UNKNOWN-001", None),
    ],
)
def test_the_control_id_prefix_is_the_fallback_platform(control_id: str, expected: str | None) -> None:
    assert _source_platform_from_result(_result(control_id=control_id)) == expected


@pytest.mark.parametrize("extra", [None, "not-a-mapping", 42, []])
def test_extra_of_the_wrong_shape_yields_no_digest_and_no_schema(extra: Any) -> None:
    """`extra` is free-form; a non-mapping must produce nothing rather than raise."""

    assert _digest_and_schema_from_result(_result(extra=extra)) == (None, None)


def test_a_digest_and_schema_are_read_when_they_are_present_and_well_formed() -> None:
    """The counterpart, so the test above cannot pass by always returning nothing."""

    result = _result(extra={"digest": "sha256:abc", "evidence_schema_id": " schema/v1 "})
    assert _digest_and_schema_from_result(result) == ("sha256:abc", "schema/v1")


def test_a_digest_without_the_sha256_prefix_is_not_read_as_one() -> None:
    assert _digest_and_schema_from_result(_result(extra={"digest": "abc"}))[0] is None


# --------------------------------------------------------------------------- #
# project_evidence
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("method", ["live", "manual", "static"])
def test_a_recognised_collection_method_is_preserved(method: str) -> None:
    projected = project_evidence(_result(method=method), ctx=FreshnessContext())
    assert projected["collection_method"] == method


@pytest.mark.parametrize("method", ["scraped", "", "LIVE-ish"])
def test_an_unrecognised_collection_method_falls_back_to_static(method: str) -> None:
    """An unknown method must not be echoed into the evidence as if the kit understood it."""

    projected = project_evidence(_result(method=method), ctx=FreshnessContext())
    assert projected["collection_method"] == "static"


@pytest.mark.parametrize("plat", ["", "   ", 42, None])
def test_a_source_platform_that_is_not_usable_text_falls_back_to_the_id(plat: Any) -> None:
    """A blank or non-string platform must not override the control-id heuristic with nothing."""

    result = _result(control_id="AZ-PLAT-034", extra={"source_platform": plat})
    assert _source_platform_from_result(result) == "azure"


def test_a_result_whose_extra_is_not_a_mapping_still_projects() -> None:
    """`collected_at` lives in `extra`; a non-mapping means no timestamp, not a crash."""

    projected = project_evidence(_result(extra="not-a-mapping"), ctx=FreshnessContext())
    assert projected["collection_method"] == "static"


def test_an_unresolvable_home_directory_disables_the_home_chain_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no home to compare against, no path can be said to lead with it."""

    from oss_policy_kit.application import evidence_projection as ep

    monkeypatch.setattr(ep, "_home_chain", lambda: ())
    assert ep._starts_with_home_chain("Users/someone/repo") is False
