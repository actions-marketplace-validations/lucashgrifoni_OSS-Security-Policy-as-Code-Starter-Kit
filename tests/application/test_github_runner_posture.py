"""Self-hosted runner posture: the three states, and the one that is neither pass nor fail.

`_gh_ephemeral_posture_outcome` looks at which workflows use `self-hosted` and which of those
also declare `ephemeral`. Persistent runner state is the risk the control exists for -- a job
that leaves credentials or a poisoned toolchain behind for the next job on the same box.

There are three answers, and the middle one had never been produced. Some workflows ephemeral
and others not is a *mixed* posture: not a clean pass, because the non-ephemeral ones still
carry the risk, and not a clean fail, because someone clearly did the work partially and the
right response is to name which files are missing the label rather than mark the control
broken.

The reason text is asserted to contain the offending filenames, since "mixed posture" with no
list is not something an operator can act on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import github as gh
from oss_policy_kit.domain.models import ControlStatus


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    return tmp_path / ".oss-policy-kit" / "evidence" / "runner-groups.json"


def _wf(tmp_path: Path, name: str) -> Path:
    path = tmp_path / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("on: push\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# no self-hosted runners at all
# --------------------------------------------------------------------------- #


def test_staying_on_github_hosted_runners_passes_on_its_own(evidence: Path) -> None:
    """No self-hosted runners and no evidence file is a real PASS, not an absence of data.

    The control is about the runner-host attack surface, and a repository that never leaves
    GitHub-hosted runners does not have one. Answering MANUAL_REVIEW here would ask an
    operator to attest something they already avoided by construction.
    """

    outcome = gh._gh_ephemeral_posture_outcome([], [], evidence)

    assert outcome is not None
    assert outcome.status is ControlStatus.PASS
    assert "No self-hosted runners" in outcome.reason


def test_no_self_hosted_but_evidence_present_defers_to_the_evidence_checks(tmp_path: Path) -> None:
    """None is the "nothing to say here" signal, and it is reached only in this one state.

    A repository with runner-groups.json has something to validate even without self-hosted
    workflows, so the helper steps aside rather than short-circuiting to a pass.
    """

    evidence = tmp_path / ".oss-policy-kit" / "evidence" / "runner-groups.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}", encoding="utf-8")

    assert gh._gh_ephemeral_posture_outcome([], [], evidence) is None


# --------------------------------------------------------------------------- #
# every self-hosted workflow is ephemeral
# --------------------------------------------------------------------------- #


def test_a_fully_ephemeral_posture_passes(tmp_path: Path, evidence: Path) -> None:
    """The clean case: every workflow that uses self-hosted also declares ephemeral."""

    paths = [_wf(tmp_path, "ci.yml"), _wf(tmp_path, "release.yml")]

    outcome = gh._gh_ephemeral_posture_outcome(paths, list(paths), evidence)

    assert outcome is not None
    assert outcome.status is ControlStatus.PASS
    assert "ephemeral" in outcome.reason


# --------------------------------------------------------------------------- #
# none of them are ephemeral
# --------------------------------------------------------------------------- #


def test_self_hosted_with_no_ephemeral_label_anywhere_is_reported(tmp_path: Path, evidence: Path) -> None:
    paths = [_wf(tmp_path, "ci.yml")]

    outcome = gh._gh_ephemeral_posture_outcome(paths, [], evidence)

    assert outcome is not None
    assert outcome.status is not ControlStatus.PASS
    assert "ci.yml" in outcome.reason
    assert outcome.remediation.strip()


# --------------------------------------------------------------------------- #
# the mixed posture -- the state that had never been produced
# --------------------------------------------------------------------------- #


def test_a_mixed_posture_is_reviewed_and_names_the_workflows_missing_the_label(tmp_path: Path, evidence: Path) -> None:
    """Neither a pass nor a fail: partially done work, and the answer has to say which files.

    Marking it FAIL would erase the distinction from a repository that did nothing, and
    passing it would ignore the workflows that still run on persistent state.
    """

    good = _wf(tmp_path, "ci.yml")
    bad = _wf(tmp_path, "nightly.yml")

    outcome = gh._gh_ephemeral_posture_outcome([good, bad], [good], evidence)

    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "nightly.yml" in outcome.reason
    assert "ci.yml" not in outcome.reason, "the compliant workflow was named as a problem"


def test_the_mixed_posture_message_lists_at_most_five_workflows(tmp_path: Path, evidence: Path) -> None:
    """A monorepo can have dozens; the reason is a pointer, not an inventory."""

    good = _wf(tmp_path, "ci.yml")
    bad = [_wf(tmp_path, f"job-{i:02d}.yml") for i in range(12)]

    outcome = gh._gh_ephemeral_posture_outcome([good, *bad], [good], evidence)

    assert outcome is not None
    named = [p.name for p in bad if p.name in outcome.reason]
    assert len(named) == 5


def test_the_mixed_posture_still_carries_every_workflow_as_evidence(tmp_path: Path, evidence: Path) -> None:
    """The message is capped; the evidence list is not, so nothing is silently dropped."""

    good = _wf(tmp_path, "ci.yml")
    bad = [_wf(tmp_path, f"job-{i:02d}.yml") for i in range(8)]
    all_self = [good, *bad]

    outcome = gh._gh_ephemeral_posture_outcome(all_self, [good], evidence)

    assert outcome is not None
    assert len(outcome.evidence_sources) == len(all_self)


@pytest.mark.parametrize("ephemeral_count", [1, 2, 3])
def test_any_shortfall_at_all_counts_as_mixed(tmp_path: Path, evidence: Path, ephemeral_count: int) -> None:
    """One workflow short of complete is still a gap; the threshold is not a majority."""

    paths = [_wf(tmp_path, f"w{i}.yml") for i in range(4)]

    outcome = gh._gh_ephemeral_posture_outcome(paths, paths[:ephemeral_count], evidence)

    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
