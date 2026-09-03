"""Azure posture the evidence does not actually establish: unknown, unsupported, or absent.

Both helpers here answer the same question in different words -- *does this evidence let us
say anything?* -- and both had branches that never ran. They are the place where an Azure
control can quietly become a pass on evidence that establishes nothing, which is the worst
outcome a compliance tool can produce: an operator reads a green control and stops looking.

So every case asserts the status is NOT `PASS`, in addition to naming the status it should
be. A helper that returned the wrong non-pass status is a smaller bug than one that returned
`PASS`, and the tests distinguish the two.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import azure as az
from oss_policy_kit.domain.models import ControlStatus


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    path = tmp_path / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# service connection authentication
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("auth", sorted(az._SCONN_ALLOWED_AUTH))
def test_a_known_authentication_value_produces_no_objection(evidence: Path, auth: str) -> None:
    """None means "nothing to report here" and lets the caller continue its own checks."""

    assert az._sconn_auth_outcome([{"name": "deploy", "authentication": auth}], evidence) is None


@pytest.mark.parametrize("auth", ["WORKLOAD_IDENTITY_FEDERATION", "  Service_Principal  "])
def test_a_known_value_is_matched_case_and_whitespace_insensitively(evidence: Path, auth: str) -> None:
    """Evidence is hand-attested; rejecting it on casing would be a false finding."""

    assert az._sconn_auth_outcome([{"name": "deploy", "authentication": auth}], evidence) is None


@pytest.mark.parametrize(
    ("label", "auth"),
    [
        ("the literal placeholder", "unknown"),
        ("the placeholder in caps", "UNKNOWN"),
        ("an empty string", ""),
        ("only whitespace", "   "),
        ("a non-string", 42),
        ("a missing field", None),
    ],
)
def test_authentication_that_says_nothing_is_not_evaluated(evidence: Path, label: str, auth: Any) -> None:
    """`unknown` is the collector admitting it could not tell. That is not a pass.

    NOT_EVALUATED rather than FAIL on purpose: the connection may well be fine, and calling
    it a failure would send an operator to fix something that is not broken.
    """

    conn: dict[str, Any] = {"name": "deploy"}
    if auth is not None:
        conn["authentication"] = auth

    outcome = az._sconn_auth_outcome([conn], evidence)

    assert outcome is not None, label
    assert outcome.status is ControlStatus.NOT_EVALUATED
    assert outcome.status is not ControlStatus.PASS


def test_an_unsupported_authentication_value_goes_to_manual_review(evidence: Path) -> None:
    """A value outside the vocabulary is a human question, and the message has to name it."""

    outcome = az._sconn_auth_outcome([{"name": "legacy-deploy", "authentication": "basic_auth"}], evidence)

    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "basic_auth" in outcome.reason
    assert "legacy-deploy" in outcome.reason, "the operator cannot act without knowing which connection"


def test_an_unnamed_connection_still_produces_a_readable_message(evidence: Path) -> None:
    outcome = az._sconn_auth_outcome([{"authentication": "basic_auth"}], evidence)

    assert outcome is not None
    assert "<unnamed>" in outcome.reason


def test_entries_that_are_not_objects_are_skipped_not_fatal(evidence: Path) -> None:
    """One malformed entry must not stop the remaining connections being checked."""

    outcome = az._sconn_auth_outcome(
        ["not-a-dict", None, {"name": "deploy", "authentication": "unknown"}],
        evidence,
    )

    assert outcome is not None
    assert outcome.status is ControlStatus.NOT_EVALUATED


def test_the_first_problem_wins_over_later_healthy_entries(evidence: Path) -> None:
    """A single unattested connection is enough; the control cannot pass around it."""

    outcome = az._sconn_auth_outcome(
        [
            {"name": "bad", "authentication": "unknown"},
            {"name": "good", "authentication": "workload_identity_federation"},
        ],
        evidence,
    )

    assert outcome is not None
    assert outcome.status is ControlStatus.NOT_EVALUATED


def test_no_connections_at_all_produces_no_objection(evidence: Path) -> None:
    assert az._sconn_auth_outcome([], evidence) is None


# --------------------------------------------------------------------------- #
# workload identity federation posture
# --------------------------------------------------------------------------- #


def test_federation_explicitly_preferred_produces_no_objection(evidence: Path) -> None:
    assert az._az_wif_posture_outcome({"federated_identity_preferred": True}, evidence) is None


def test_federation_explicitly_not_preferred_fails(evidence: Path) -> None:
    """An explicit False is a real, attested negative -- the one case that is a FAIL."""

    outcome = az._az_wif_posture_outcome({"federated_identity_preferred": False}, evidence)

    assert outcome is not None
    assert outcome.status is ControlStatus.FAIL
    assert outcome.remediation.strip()


@pytest.mark.parametrize(
    ("label", "posture"),
    [
        ("no posture object", None),
        ("posture is not an object", "federated"),
        ("the field is absent", {"something_else": True}),
    ],
)
def test_a_posture_that_never_states_the_flag_is_reviewed_not_failed(evidence: Path, label: str, posture: Any) -> None:
    """Absent is not the same as False; failing here would invent an attestation."""

    outcome = az._az_wif_posture_outcome(posture, evidence)

    assert outcome is not None, label
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert outcome.status is not ControlStatus.PASS


@pytest.mark.parametrize("pref", ["true", "True", 1, "yes", 0, None])
def test_a_non_boolean_flag_is_reviewed_rather_than_coerced(evidence: Path, pref: Any) -> None:
    """The string "true" is what an unresolved template looks like.

    Coercing it would claim a federation posture nobody attested, which is exactly the
    silent false pass these helpers exist to prevent. Note `1` and `0` are included: they
    are truthy/falsy in Python but are not the boolean the schema asks for.
    """

    outcome = az._az_wif_posture_outcome({"federated_identity_preferred": pref}, evidence)

    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert outcome.status is not ControlStatus.PASS
