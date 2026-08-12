"""SAST evidence that cannot be counted is unknown, and unknown is neither clean nor a crash.

`SAST-SEMGREP-064` reads a JSON file off disk, so its contents carry exactly as much authority
as the file it came from -- which may have been hand-edited, truncated, or written by something
other than `scan-sast`. The schema says `findings_by_severity` is an object of non-negative
integers and `findings_total` a non-negative integer; every other shape is a tally the reader
cannot read.

Two failures used to live here, and both were reproducible through the real CLI:

- `{"ERROR": "many"}` raised `ValueError` out of `int()` and surfaced as
  `Unexpected error: invalid literal for int() with base 10: 'many'`, exit 3.
- `["ERROR"]` was coerced to `{}` and reported `pass` at *high* confidence -- an unreadable
  scan presented to the adopter as a clean one, which is the worse of the two.

Both now report `manual-review-required`, and the tests below assert the legitimate directions
alongside them so the strictness cannot swallow real verdicts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application.evaluators import cicd
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

_SCHEMA = "oss-policy-kit/evidence/sast-semgrep/1.0"


def _ctx(root: Path) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="appsec-sast-sca-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _evidence(root: Path, **payload: Any) -> None:
    path = root / ".oss-policy-kit" / "evidence" / "sast-semgrep.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"schema_version": _SCHEMA, "status": "ok", "findings_total": 0} | payload
    path.write_text(json.dumps(body), encoding="utf-8")


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("a severity map that is a list", {"findings_by_severity": ["ERROR"]}),
        ("a severity map that is a string", {"findings_by_severity": "ERROR=2"}),
        ("a count that is not a number", {"findings_by_severity": {"ERROR": "many"}}),
        ("a count that is a nested object", {"findings_by_severity": {"ERROR": {"n": 2}}}),
        ("a count that is null", {"findings_by_severity": {"ERROR": None}}),
        ("a negative count", {"findings_by_severity": {"ERROR": -1}}),
        ("a total that is not a number", {"findings_total": "two"}),
        ("a negative total", {"findings_total": -1}),
    ],
)
def test_an_uncountable_tally_is_never_reported_as_a_clean_scan(
    label: str, payload: dict[str, Any], tmp_path: Path
) -> None:
    """Neither `pass` nor a traceback: the honest answer is that a human has to look."""

    _evidence(tmp_path, **payload)
    outcome = cicd.eval_sast_semgrep_064(_ctx(tmp_path))
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED, label
    assert "countable" in outcome.reason


def test_true_is_not_one_finding(tmp_path: Path) -> None:
    """`bool` is an `int` subclass, so an unguarded count would read `true` as a single finding."""

    _evidence(tmp_path, findings_by_severity={"ERROR": True})
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_a_clean_run_still_passes_and_reports_its_total(tmp_path: Path) -> None:
    """The counterpart: strictness that refused everything would be just as wrong."""

    _evidence(tmp_path, findings_total=4, findings_by_severity={"WARNING": 4})
    outcome = cicd.eval_sast_semgrep_064(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert "4 total finding(s)" in outcome.reason


def test_an_absent_severity_map_is_read_as_no_findings(tmp_path: Path) -> None:
    """Missing is not malformed; the file simply declares nothing to count."""

    _evidence(tmp_path, findings_by_severity=None)
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status is ControlStatus.PASS


@pytest.mark.parametrize("counts", [{"ERROR": 2}, {"HIGH": 1}, {"CRITICAL": 1}])
def test_blocking_severities_still_fail(counts: dict[str, int], tmp_path: Path) -> None:
    _evidence(tmp_path, findings_total=sum(counts.values()), findings_by_severity=counts)
    assert cicd.eval_sast_semgrep_064(_ctx(tmp_path)).status is ControlStatus.FAIL
