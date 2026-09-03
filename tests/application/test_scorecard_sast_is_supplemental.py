"""A Scorecard check name is a hint that SAST exists, not evidence that it ran here.

`SEC-CODEQL-010` prefers a dedicated workflow file, then a pinned CodeQL action, then any SAST
keyword in CI. Only when all three come up empty does it consult the Scorecard export -- and
what it finds there is a *check name*, produced by a tool that looked at the repository from
outside. It says nothing about whether the scan ran on this commit or what it found.

So the fallback passing is fine; the fallback passing *quietly* is not. This asserts the three
things that keep it honest: low confidence, an operational warning, and a reason that says
"supplemental" out loud.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, ScorecardCheck
from oss_policy_kit.application.evaluators import cicd
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(root: Path, *check_names: str, raw_path: str | None = "scorecard.json") -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="github-level-2",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=ScorecardBundle(
            checks=[ScorecardCheck(name=n, score=10) for n in check_names],
            raw_path=raw_path,
        ),
    )


@pytest.mark.parametrize("check_name", ["CodeQL", "Code-QL", "SAST", "sast-scanning"])
def test_a_scorecard_sast_check_passes_the_control_as_supplemental(check_name: str, tmp_path: Path) -> None:
    outcome = cicd.eval_sec_codeql_010(_ctx(tmp_path, "Branch-Protection", check_name))

    assert outcome.status is ControlStatus.PASS
    assert outcome.confidence == "low", "an external check name is the weakest signal the control accepts"
    assert "supplemental" in outcome.reason.lower()
    assert outcome.operational_warnings, "passing on a third-party signal has to be visible in the report"
    assert outcome.evidence_sources == ["scorecard.json"]


def test_an_undated_export_without_a_path_still_reports_a_source_list(tmp_path: Path) -> None:
    """`raw_path` is optional; the outcome must not carry `None` into the evidence list."""

    outcome = cicd.eval_sec_codeql_010(_ctx(tmp_path, "CodeQL", raw_path=None))
    assert outcome.evidence_sources == ["scorecard"]


def test_scorecard_checks_unrelated_to_sast_do_not_pass_the_control(tmp_path: Path) -> None:
    """The counterpart: matching loosely here would pass every repository with a Scorecard file."""

    outcome = cicd.eval_sec_codeql_010(_ctx(tmp_path, "Branch-Protection", "Signed-Releases", "Fuzzing"))

    assert outcome.status is ControlStatus.FAIL
    assert "No CodeQL" in outcome.reason
