"""Engine decisions that only show up on unusual input.

Four separate things live here, and each one is a place where being wrong is quiet:

* whether a repository has *real* evidence, as opposed to a directory full of unfilled
  templates or unreadable files -- this gates the hard-gate warning, so getting it wrong
  either nags every clean run or stays silent on a repository with no usable evidence at all;
* whether a waiver in a state other than approved/active is allowed to change a verdict --
  it must not, or a draft or revoked waiver silently suppresses a failure;
* what the scorecard supplemental block claims it did, in each of the four situations it can
  find itself in -- saying "no influence" when it did influence, or the reverse, misleads the
  reader about where a verdict came from;
* what happens when a profile names a control the catalog does not define, or one with no
  evaluator behind it. Both must fail loudly at load rather than quietly evaluating to
  nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, ScorecardCheck
from oss_policy_kit.application import engine
from oss_policy_kit.application.loader import ControlSpec, ProfileSpec, bundled_kit_root, load_profile_by_id
from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.domain.models import ControlResult, ControlStatus, WaiverRecord
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _result(control_id: str, status: ControlStatus, reason: str) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        title="t",
        category="c",
        status=status,
        profile="p",
        evidence_sources=[],
        confidence="high",
        reason=reason,
        remediation="r",
    )


# --------------------------------------------------------------------------- #
# _has_real_evidence
# --------------------------------------------------------------------------- #


def test_no_evidence_directory_is_not_real_evidence(tmp_path: Path) -> None:
    assert engine._has_real_evidence(tmp_path / "nope") is False


def test_a_directory_of_templates_is_not_real_evidence(tmp_path: Path) -> None:
    """Scaffolded-but-unfilled files must not count as having attested anything."""

    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "a.json").write_text(json.dumps({"attested_by": "REPLACE_ME_USER"}), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps({"owner": "TODO"}), encoding="utf-8")
    assert engine._has_real_evidence(tmp_path) is False


def test_unreadable_evidence_is_skipped_rather_than_counted(tmp_path: Path) -> None:
    """A corrupt file is not evidence, and must not take the check down either."""

    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    assert engine._has_real_evidence(tmp_path) is False


def test_one_filled_in_file_among_templates_is_enough(tmp_path: Path) -> None:
    (tmp_path / "a.json").write_text(json.dumps({"attested_by": "REPLACE_ME_USER"}), encoding="utf-8")
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "z.json").write_text(json.dumps({"attested_by": "platform-team"}), encoding="utf-8")
    assert engine._has_real_evidence(tmp_path) is True


# --------------------------------------------------------------------------- #
# _apply_waiver
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", ["draft", "revoked", "expired", "pending", ""])
def test_a_waiver_that_is_not_approved_changes_nothing(status: str) -> None:
    """Only approved/active waivers may move a verdict; anything else is inert."""

    waiver = WaiverRecord(
        control_id="GOV-SEC-001",
        justification="j",
        owner="o",
        status=status,
        expires_at=None,
        applies_to=None,
    )
    new_status, applied = engine._apply_waiver(ControlStatus.FAIL, waiver)
    assert new_status is ControlStatus.FAIL
    assert applied is None


@pytest.mark.parametrize("status", ["approved", "ACTIVE"])
def test_an_approved_waiver_does_move_a_failure(status: str) -> None:
    """The counterpart: without this the test above would pass with waivers disabled."""

    waiver = WaiverRecord(
        control_id="GOV-SEC-001",
        justification="j",
        owner="o",
        status=status,
        expires_at=None,
        applies_to=None,
    )
    new_status, applied = engine._apply_waiver(ControlStatus.FAIL, waiver)
    assert new_status is not ControlStatus.FAIL
    assert applied is waiver


def test_no_waiver_leaves_the_status_alone() -> None:
    assert engine._apply_waiver(ControlStatus.FAIL, None) == (ControlStatus.FAIL, None)


# --------------------------------------------------------------------------- #
# _build_scorecard_supplemental
# --------------------------------------------------------------------------- #


def _bundle(n_checks: int) -> ScorecardBundle:
    return ScorecardBundle(
        checks=[ScorecardCheck(name=f"c{i}", score=5) for i in range(n_checks)],
        raw_path="scorecard.json",
    )


def test_no_scorecard_produces_no_supplemental_block() -> None:
    blob, warnings = engine._build_scorecard_supplemental(None, [])
    assert blob is None
    assert warnings == []


def test_a_scorecard_with_zero_checks_warns_that_it_will_not_help() -> None:
    """Parsed fine but carries nothing usable -- say so rather than imply it was used."""

    blob, warnings = engine._build_scorecard_supplemental(_bundle(0), [])
    assert blob is not None
    assert any("zero recognizable check entries" in w for w in warnings), warnings


def test_supplemental_reports_when_it_actually_changed_an_outcome() -> None:
    results = [_result("SEC-CODEQL-010", ControlStatus.PASS, "Scorecard export references SAST")]
    blob, _ = engine._build_scorecard_supplemental(_bundle(3), results)
    assert blob is not None
    assert "changed outcomes for" in blob["explanation"]


def test_supplemental_says_so_when_the_control_was_already_satisfied_in_repo() -> None:
    """A pass that did not come from the scorecard must not be credited to it."""

    results = [_result("SEC-CODEQL-010", ControlStatus.PASS, "CodeQL workflow found in .github/workflows")]
    blob, _ = engine._build_scorecard_supplemental(_bundle(3), results)
    assert blob is not None
    assert "already satisfied from in-repo workflows" in blob["explanation"]


def test_supplemental_points_at_the_fix_when_the_control_failed() -> None:
    results = [_result("SEC-CODEQL-010", ControlStatus.FAIL, "No SAST in CI")]
    blob, _ = engine._build_scorecard_supplemental(_bundle(3), results)
    assert blob is not None
    assert "add CodeQL or equivalent SAST in CI" in blob["explanation"]


def test_supplemental_admits_it_influenced_nothing_when_the_control_is_absent() -> None:
    """Profile without SEC-CODEQL-010 at all: no influence, and no invented explanation."""

    blob, _ = engine._build_scorecard_supplemental(_bundle(3), [_result("GOV-SEC-001", ControlStatus.PASS, "ok")])
    assert blob is not None
    assert "did not influence any control outcomes" in blob["explanation"]


# --------------------------------------------------------------------------- #
# Verbose output
# --------------------------------------------------------------------------- #


def test_a_very_long_reason_is_truncated_in_the_verbose_line() -> None:
    """The verbose line is a progress trace, not the report; the JSON keeps the full text."""

    seen: list[str] = []
    ctx = engine.EvalContext(
        repo_root=Path("."),
        profile_id="p",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        verbose_emit=seen.append,
    )
    outcome = engine.EvalOutcome(
        status=ControlStatus.FAIL,
        reason="x" * 400,
        remediation="r",
        evidence_sources=[],
        confidence="low",
    )
    engine._emit_verbose_outcome(ctx, outcome)

    assert seen, "verbose_emit was never called"
    assert "..." in seen[0]
    assert len(seen[0]) < 400


# --------------------------------------------------------------------------- #
# Profile / catalog mismatches
# --------------------------------------------------------------------------- #


def test_a_profile_naming_an_unknown_control_fails_loudly() -> None:
    """Skipping it would silently shrink the profile the operator thinks they ran."""

    ctx, profile = _min_ctx(), _min_profile()
    with pytest.raises(LoadError, match="unknown control"):
        engine._evaluate_control("NO-SUCH-001", ctx, profile, {}, {}, [])


def test_a_control_with_no_evaluator_behind_it_fails_loudly() -> None:
    """A catalog entry without an implementation must not evaluate to nothing."""

    spec = ControlSpec(id="GOV-GHOST-999", title="Ghost", category="governance", automation="manual")
    ctx, profile = _min_ctx(), _min_profile()
    with pytest.raises(LoadError, match="No evaluator implemented"):
        engine._evaluate_control("GOV-GHOST-999", ctx, profile, {"GOV-GHOST-999": spec}, {}, [])


def _min_ctx() -> engine.EvalContext:
    return engine.EvalContext(
        repo_root=Path("."),
        profile_id="p",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _min_profile() -> ProfileSpec:
    return load_profile_by_id(bundled_kit_root(), "github-level-1")
