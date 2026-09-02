"""A third-party evaluator that RETURNS something unusable must not take the run down.

The guard added for a plugin that raises stopped there. A plugin that imported cleanly,
ran cleanly and handed back an outcome the kit cannot use reached `ControlResult` -- which
now cleans prose and settles confidence at construction -- and blew up there, outside the
guard.

Measured through the CLI, one control of `github-level-1` served by a plugin:

    returns confidence=42     exit 3, no report, "'int' object has no attribute 'strip'"
    returns reason=None       exit 3, no report, "'NoneType' object has no attribute 'isprintable'"

Exit 3 is what docs/cli-reference.md reserves for a defect in THIS kit, and the operator
lost the other thirteen verdicts. v10.0.17 behaves identically, verified against a worktree
at the tag, so this is the guard finishing the job it started rather than a regression.

The asymmetry from the first guard is kept and asserted: a BUILT-IN evaluator returning
garbage is a defect in this kit and still exits 3.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY, PLUGIN_CONTROL_IDS
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.models import ControlStatus, EvalOutcome

runner = CliRunner()

#: A control `github-level-1` actually evaluates; sabotaging one outside the profile proves
#: nothing, which is how the first reproduction of the raising case came back green.
_CONTROL = "GOV-SEC-001"


def _repo(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    return target


def _outcome(**over: Any) -> EvalOutcome:
    base: dict[str, Any] = {
        "status": ControlStatus.FAIL,
        "reason": "r",
        "remediation": "m",
        "evidence_sources": [],
        "confidence": "low",
    }
    base.update(over)
    return EvalOutcome(**base)


_GARBAGE: dict[str, Any] = {
    "confidence-is-an-int": lambda _ctx: _outcome(confidence=42),
    "reason-is-none": lambda _ctx: _outcome(reason=None),
    "remediation-is-a-list": lambda _ctx: _outcome(remediation=["fix", "it"]),
    "status-is-a-string": lambda _ctx: _outcome(status="fail"),
    "evidence-sources-is-a-string": lambda _ctx: _outcome(evidence_sources="README.md"),
    "not-an-outcome-at-all": lambda _ctx: {"status": "fail"},
    "returns-none": lambda _ctx: None,
}


@pytest.fixture
def swapped(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    original = EVALUATOR_REGISTRY[_CONTROL]

    def _install(evaluator: Any, *, as_plugin: bool) -> None:
        monkeypatch.setitem(EVALUATOR_REGISTRY, _CONTROL, evaluator)
        if as_plugin:
            PLUGIN_CONTROL_IDS.add(_CONTROL)

    try:
        yield _install
    finally:
        EVALUATOR_REGISTRY[_CONTROL] = original
        PLUGIN_CONTROL_IDS.discard(_CONTROL)


def _run(tmp_path: Path) -> tuple[int, Path, str]:
    out = tmp_path / "out"
    result = runner.invoke(
        app, ["evaluate", "--target", str(_repo(tmp_path)), "--profile", "github-level-1", "--output-dir", str(out)]
    )
    return result.exit_code, out / "evaluation-report.json", " ".join(result.output.split())


@pytest.mark.parametrize("shape", sorted(_GARBAGE), ids=sorted(_GARBAGE))
def test_a_plugin_returning_garbage_leaves_the_rest_of_the_run_intact(shape: str, tmp_path: Path, swapped: Any) -> None:
    swapped(_GARBAGE[shape], as_plugin=True)

    exit_code, report_path, output = _run(tmp_path)

    assert exit_code != 3, (
        f"exit 3 for a third-party outcome shaped {shape!r}. That code means a defect in this "
        f"kit, and the operator loses every other verdict with it. Output: {output[-300:]!r}"
    )
    assert report_path.is_file(), "no report was written, so the whole run was lost to one plugin"

    report = json.loads(report_path.read_text(encoding="utf-8"))
    broken = next(c for c in report["controls"] if c["id"] == _CONTROL)
    assert broken["state"] == "UNKNOWN", (
        f"the control the plugin failed on reports {broken['state']!r}. A plugin that returned "
        "nothing usable established nothing, so any other state is a claim the kit cannot make."
    )
    assert "malformed" in broken["message"], f"the reason does not say what happened: {broken['message']!r}"
    assert len(report["controls"]) > 1, "the other controls did not run"


def test_a_built_in_returning_garbage_is_still_a_kit_defect(tmp_path: Path, swapped: Any) -> None:
    """The asymmetry, asserted. Swallowing this would hide real defects in this kit."""

    swapped(_GARBAGE["confidence-is-an-int"], as_plugin=False)

    exit_code, report_path, _output = _run(tmp_path)

    assert exit_code == 3, (
        f"a BUILT-IN evaluator returned garbage and the run exited {exit_code}. That is this kit's "
        "own failure and exit 3 is the honest answer; catching it here would hide it."
    )
    assert not report_path.exists()


def test_a_well_formed_plugin_outcome_passes_through_untouched(tmp_path: Path, swapped: Any) -> None:
    """The other half: the shape check must not reject an outcome the kit can use."""

    swapped(lambda _ctx: _outcome(status=ControlStatus.PASS, reason="fine", confidence="high"), as_plugin=True)

    exit_code, report_path, _output = _run(tmp_path)

    assert exit_code in (0, 1)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    control = next(c for c in report["controls"] if c["id"] == _CONTROL)
    assert control["state"] == "PASS"
    assert control["confidence"] == "high"
