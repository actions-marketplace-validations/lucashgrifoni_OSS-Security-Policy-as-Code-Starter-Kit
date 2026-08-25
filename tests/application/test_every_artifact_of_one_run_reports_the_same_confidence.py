"""One run must not produce artifacts that disagree about the same field.

`confidence` was normalized by two of the four writers. The JSON report and the SARIF
export both called `normalize_confidence`; the Markdown report and the terminal table
printed the evaluator's raw string.

So an evaluator answering `"Strong"` was reported as `high` in two artifacts and `Strong`
in the other two, and one answering a word the kit cannot place was reported as `low` --
the deliberate conservative fallback -- in two artifacts and verbatim in the other two.
The second case is the worse one: the Markdown showed an unexamined claim about evidence
strength beside a JSON that had already refused it.

Reach: the bundled evaluators only ever return `high`, `medium` or `low`, all of which
normalize to themselves, so this needed a third-party evaluator to surface. `"exact"` also
appears as a confidence literal in the kit and normalizes to `low`, but that one belongs
to `CorrelationInfo` in findings/1.0 -- a different model, not this field.

The fix settles the value in `ControlResult` and the two writers that normalized on their
own no longer do, so there is exactly one place that decides. A second call would have
been a no-op no test could tell apart from its absence.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application import evaluators as ev
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
    EvalOutcome,
    normalize_confidence,
)

runner = CliRunner()

#: A control `github-level-1` really evaluates, so the substituted evaluator reaches the
#: report. One outside the profile would leave every assertion below reading a control
#: that never ran.
_CONTROL = "GOV-SEC-001"


@pytest.fixture
def swap_evaluator() -> Iterator[Any]:
    """Replace one evaluator for the duration of a test; the registry is session state."""

    original = ev.EVALUATOR_REGISTRY[_CONTROL]

    def _install(confidence: str) -> None:
        def _evaluator(_ctx: object) -> EvalOutcome:
            return EvalOutcome(
                status=ControlStatus.FAIL,
                reason="a third-party evaluator reported this",
                remediation="fix it",
                evidence_sources=[],
                confidence=confidence,
            )

        ev.EVALUATOR_REGISTRY[_CONTROL] = _evaluator

    try:
        yield _install
    finally:
        ev.EVALUATOR_REGISTRY[_CONTROL] = original


def _run(tmp_path: Path) -> tuple[str, str, str]:
    """(json value, markdown cell, terminal output) for `_CONTROL`'s confidence."""

    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    out = tmp_path / "out"

    result = runner.invoke(
        app, ["evaluate", "--target", str(repo), "--profile", "github-level-1", "--output-dir", str(out)]
    )
    assert result.exit_code in (0, 1), f"exit {result.exit_code}: {result.output[-300:]!r}"

    payload = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    control = next(c for c in payload["controls"] if c["id"] == _CONTROL)

    markdown = (out / "evaluation-report.md").read_text(encoding="utf-8")
    row = next(line for line in markdown.splitlines() if line.startswith(f"| `{_CONTROL}`"))

    return control["confidence"], row.split("|")[6].strip(), " ".join(result.output.split())


@pytest.mark.parametrize(
    "answered,expected",
    [("Strong", "high"), ("moderate", "medium"), ("weak", "low"), ("banana", "low"), ("", "none")],
    ids=["Strong", "moderate", "weak", "unrecognized", "empty"],
)
def test_the_json_and_the_markdown_agree(answered: str, expected: str, tmp_path: Path, swap_evaluator: Any) -> None:
    swap_evaluator(answered)

    from_json, from_markdown, _terminal = _run(tmp_path)

    assert from_json == expected
    assert from_markdown == expected, (
        f"an evaluator answered {answered!r} and one run reported {from_json!r} in the JSON "
        f"and {from_markdown!r} in the Markdown beside it."
    )


def test_the_terminal_does_not_show_the_unexamined_word(tmp_path: Path, swap_evaluator: Any) -> None:
    """The fourth surface. A word the kit cannot place must not be presented as a grade."""

    swap_evaluator("banana")

    _from_json, _from_markdown, terminal = _run(tmp_path)

    assert "banana" not in terminal, (
        "the terminal table printed a confidence the kit refused to accept in the JSON, "
        "which is the artifact an operator actually looks at first."
    )


def test_a_bundled_confidence_is_unchanged(tmp_path: Path) -> None:
    """The other half: the bundled vocabulary must pass through untouched.

    Every built-in returns `high`, `medium` or `low`. A normalization that altered those
    would rewrite every report in the suite while satisfying the assertions above.
    """

    from_json, from_markdown, _terminal = _run(tmp_path)

    assert from_json == from_markdown
    assert from_json in {"high", "medium", "low", "none"}


def test_the_result_object_settles_the_value_once() -> None:
    """Built directly, so the guarantee is the type's and not a writer's."""

    result = ControlResult(
        control_id="X-1",
        title="t",
        category="c",
        status=ControlStatus.FAIL,
        profile="p",
        evidence_sources=[],
        confidence="Strong",
        reason="r",
        remediation="m",
    )

    assert result.confidence == "high"


def test_normalizing_twice_changes_nothing() -> None:
    """What lets the value be settled at construction instead of at every writer."""

    for word in ("Strong", "moderate", "weak", "banana", "", "n/a"):
        once = normalize_confidence(word)
        assert normalize_confidence(once) == once, f"{word!r} -> {once!r} is not stable"
