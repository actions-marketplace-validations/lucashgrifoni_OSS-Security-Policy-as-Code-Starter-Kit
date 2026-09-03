"""The gate that stands between a template digest and an attestation the kit would believe.

Four artifact-attestation controls -- SBOM and provenance, on AWS and on Azure -- hand their
digests to `_digest_gate_outcome` before reading any posture flag. What it protects is narrow
and worth stating: a control that says an SBOM covers a release artifact is claiming the two
hashes were compared, so a digest that is really a scaffold placeholder must never reach the
posture check and turn into a pass.

The two refusals are deliberately different verdicts, and the tests assert that difference:

- a *placeholder* digest is `manual-review-required` -- the file was scaffolded and never
  filled in, which is a human's job to finish, not a machine's to judge;
- a *malformed* digest is `not-evaluated` -- the kit cannot interpret the value at all, and
  saying anything else about it would be a guess.

The malformed branch is currently unreachable through the four controls: their schemas pin
`digest_sha256` to `^[a-f0-9]{64}$`, and every shape `is_valid_sha256_digest` rejects inside
that pattern is already caught as a placeholder. It is kept, and tested here at the helper,
because the guard is what makes loosening one of those schemas safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators._shared import _digest_gate_outcome
from oss_policy_kit.domain.models import ControlStatus

_REAL = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
_OTHER = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"


@pytest.mark.parametrize(
    ("label", "digest"),
    [
        ("all zeroes", "0" * 64),
        ("a single repeated character", "a" * 64),
        ("a known template digest", "f" * 64),
        ("a short unit repeated to length", "deadbeef" * 8),
    ],
)
def test_a_placeholder_digest_sends_the_control_to_a_human(label: str, digest: str) -> None:
    """A scaffold nobody filled in is an unfinished attestation, not a failed one."""

    outcome = _digest_gate_outcome(Path("evidence.json"), [digest])

    assert outcome is not None, label
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED


@pytest.mark.parametrize(
    ("label", "digest"),
    [
        ("too short", "abc123"),
        ("hex with a prefix", f"sha256:{_REAL}"),
        ("not hex at all", "z" * 64),
        ("empty", ""),
    ],
)
def test_a_malformed_digest_leaves_the_control_unevaluated(label: str, digest: str) -> None:
    """The kit cannot compare what it cannot read, and must not pretend otherwise."""

    outcome = _digest_gate_outcome(Path("evidence.json"), [digest])

    assert outcome is not None, label
    assert outcome.status is ControlStatus.NOT_EVALUATED


def test_real_digests_are_waved_through() -> None:
    """The counterpart: a gate that refused everything would fail every honest adopter."""

    assert _digest_gate_outcome(Path("evidence.json"), [_REAL, _OTHER]) is None


@pytest.mark.parametrize("rendering", [_REAL.upper(), f"  {_REAL}\n", f" {_REAL.upper()} "])
def test_the_same_hash_written_differently_is_still_the_same_hash(rendering: str) -> None:
    """Case and surrounding whitespace are rendering, not content.

    Digests get copied out of tools that print them uppercase, and out of files that end with a
    newline. Refusing those would report a malformed digest to an adopter holding a correct one.
    """

    assert _digest_gate_outcome(Path("evidence.json"), [rendering]) is None


def test_nothing_to_check_is_not_a_refusal() -> None:
    assert _digest_gate_outcome(Path("evidence.json"), []) is None


def test_the_first_bad_digest_decides_and_a_placeholder_outranks_a_real_one() -> None:
    """Order matters only in that a single bad digest is enough to stop the control."""

    outcome = _digest_gate_outcome(Path("evidence.json"), [_REAL, "0" * 64])

    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_the_refusal_points_at_the_evidence_file(tmp_path: Path) -> None:
    """Whichever way it refuses, the operator has to know which file to go and fix."""

    evidence = tmp_path / "aws-sbom-artifact.json"
    outcome = _digest_gate_outcome(evidence, ["0" * 64])

    assert outcome is not None
    assert outcome.evidence_sources == [str(evidence.resolve())]
