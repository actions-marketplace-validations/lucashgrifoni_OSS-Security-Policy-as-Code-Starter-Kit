"""A third-party evaluator that raises must not take the whole run down.

The plugin loader already holds this line. Its ``except Exception`` carries the comment
``one broken plugin must not break the kit`` -- but it guards only the IMPORT. Nothing guarded
the CALL, so a plugin that imported cleanly and raised while evaluating ended the run.

Measured through the CLI, with one control of `github-level-1` served by a raising evaluator:

    exit 3, no report written at all, and stderr reading
    "Unexpected error: <the plugin's own message>"

Exit 3 is what docs/cli-reference.md reserves for a defect in THIS kit, so the kit took the
blame for third-party code, and the operator lost the other thirteen verdicts along with it.

The control is `manual-review-required` now, which is what this project already says about
anything it could not establish. The run finishes and the report is written.

The asymmetry is deliberate and is asserted below: a BUILT-IN evaluator that raises still
exits 3 with no report. That really is a defect in this kit, and swallowing it would hide the
class of failure this guard is imitating.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY, PLUGIN_CONTROL_IDS
from oss_policy_kit.cli.main import app

runner = CliRunner()

#: A control the `github-level-1` profile actually evaluates. Sabotaging one outside the
#: profile proves nothing -- the first attempt at this reproduction did exactly that and
#: came back green.
_CONTROL = "GOV-SEC-001"


def _repo(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "README.md").write_text("# demo\n", encoding="utf-8")
    return target


def _exploding(_ctx: object) -> object:
    raise RuntimeError("third-party evaluator blew up mid-evaluation")


@pytest.fixture
def sabotaged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(EVALUATOR_REGISTRY, _CONTROL, _exploding)


def test_a_raising_plugin_leaves_the_rest_of_the_run_intact(tmp_path: Path, sabotaged: None) -> None:
    out = tmp_path / "out"
    PLUGIN_CONTROL_IDS.add(_CONTROL)
    try:
        result = runner.invoke(
            app, ["evaluate", "--target", str(_repo(tmp_path)), "--profile", "github-level-1", "--output-dir", str(out)]
        )
    finally:
        # The registry is module state shared by the whole session, so the marker comes back
        # off even when the assertions below fail.
        PLUGIN_CONTROL_IDS.discard(_CONTROL)

    assert result.exit_code != 3, (
        f"exit 3 for a third-party failure. That code means a defect in this kit, and the "
        f"operator loses every other verdict with it. Output: {result.output[-300:]!r}"
    )
    report_path = out / "evaluation-report.json"
    assert report_path.is_file(), "no report was written, so the whole run was lost to one plugin"

    report = json.loads(report_path.read_text(encoding="utf-8"))
    broken = next(c for c in report["controls"] if c["id"] == _CONTROL)
    assert broken["state"] == "UNKNOWN", (
        f"the control the plugin failed on reports {broken['state']!r}. A plugin that raised "
        "established nothing, so any state other than unknown is a claim the kit cannot make."
    )
    assert len(report["controls"]) > 1, "the other controls did not run"


def test_a_raising_built_in_is_still_a_kit_defect(tmp_path: Path, sabotaged: None) -> None:
    """The asymmetry, asserted. Swallowing this would hide real defects in this kit."""

    out = tmp_path / "out"
    result = runner.invoke(
        app, ["evaluate", "--target", str(_repo(tmp_path)), "--profile", "github-level-1", "--output-dir", str(out)]
    )

    assert result.exit_code == 3, (
        f"a BUILT-IN evaluator raised and the run exited {result.exit_code}. That is this kit's "
        "own failure and exit 3 is the honest answer; catching it here would hide it."
    )
    assert not (out / "evaluation-report.json").exists()
