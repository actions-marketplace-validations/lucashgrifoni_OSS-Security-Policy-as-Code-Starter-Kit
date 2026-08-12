"""Three commands, three things they must not do quietly.

`export-policy --validate` exists because a policy pack that will not load is worse than no pack
at all: it lands in someone's CI, the gate goes green because the engine has nothing to
evaluate, and nobody notices. So a validation failure has to stop the write, not warn about it.

`emit-insights --merge` exists so a project with its own `security-insights.yml` can adopt what
the kit found without losing what they already wrote. The fragment therefore has to be *stable*
-- the fields the kit regenerates on every run are stripped, because a fragment that churns is
one nobody will merge twice.

`ingest-scorecard` names files in a way an operator can act on, and refuses ones it will not
read. Both matter more than they look: the display path is what an adopter pastes into a ticket,
and the size ceiling is what stops a hostile Scorecard JSON from being read at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from oss_policy_kit.cli import emit_insights as ei
from oss_policy_kit.cli import export_policy as ep
from oss_policy_kit.cli import ingest_scorecard as isc
from oss_policy_kit.cli.main import app

runner = CliRunner()


# --------------------------------------------------------------------------- #
# export-policy --validate
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "text", "fragment"),
    [
        ("no fidelity header", "expr == true\n", "missing fidelity-boundary header"),
        ("unbalanced parentheses", "# FIDELITY BOUNDARY\nhas(x\n", "unbalanced parentheses"),
        ("nothing but comments", "# FIDELITY BOUNDARY\n# nothing here\n", "no expressions emitted"),
    ],
)
def test_cel_output_that_would_not_load_is_reported_by_name(label: str, text: str, fragment: str) -> None:
    assert any(fragment in e for e in ep._validate_cel(text)), label


def test_well_formed_cel_reports_nothing() -> None:
    """The counterpart: a validator that complains about good output is one people disable."""

    assert ep._validate_cel("# FIDELITY BOUNDARY\nhas(controls.CI_PIN_008)\n") == []


def test_a_validation_failure_stops_the_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit 1 with the reasons on stderr, and no file: a broken pack must not reach CI."""

    out = tmp_path / "policy.cel"
    monkeypatch.setitem(ep._RENDERERS, "cel", lambda *_a, **_k: "has(x\n")
    result = runner.invoke(
        app, ["export-policy", "--profile", "github-level-2", "--format", "cel", "--output", str(out), "--validate"]
    )

    assert result.exit_code == 1, result.output
    assert "validation error" in result.output
    assert "missing fidelity-boundary header" in result.output
    assert "unbalanced parentheses" in result.output
    assert not out.exists(), "a refusal that still writes the file is not a refusal"


def test_the_same_broken_output_is_written_when_validation_is_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--validate` is opt-in; without it the command does what it was told."""

    out = tmp_path / "policy.cel"
    monkeypatch.setitem(ep._RENDERERS, "cel", lambda *_a, **_k: "has(x\n")
    result = runner.invoke(
        app, ["export-policy", "--profile", "github-level-2", "--format", "cel", "--output", str(out)]
    )

    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8") == "has(x\n"


# --------------------------------------------------------------------------- #
# emit-insights --merge
# --------------------------------------------------------------------------- #


def test_the_merge_fragment_drops_the_fields_that_change_on_every_run(tmp_path: Path) -> None:
    """A fragment that churns is one nobody will merge a second time."""

    out = tmp_path / "fragment.yml"
    result = runner.invoke(app, ["emit-insights", "--target", str(tmp_path), "--output", str(out), "--merge"])

    assert result.exit_code == 0, result.output
    assert "merge fragment" in result.output

    text = out.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    assert "project-lifecycle" not in doc
    assert "last-updated" not in doc.get("header", {})
    assert "last-reviewed" not in doc.get("header", {})
    assert text.startswith("#"), "the fragment has to say what it is before it says anything else"


def test_the_same_run_twice_produces_the_same_fragment(tmp_path: Path) -> None:
    """Stability is the whole point; asserting the fields are absent does not prove it."""

    first = tmp_path / "a.yml"
    second = tmp_path / "b.yml"
    for out in (first, second):
        assert (
            runner.invoke(app, ["emit-insights", "--target", str(tmp_path), "--output", str(out), "--merge"]).exit_code
            == 0
        )

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


def test_a_document_without_a_header_block_is_not_a_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The stripping step reads whatever the builder returned; it must not assume a shape."""

    monkeypatch.setattr(ei, "_build_insights_document", lambda _t: {"header": "not-a-mapping"})
    fragment = ei._build_insights_fragment(tmp_path)

    assert fragment == {"header": "not-a-mapping"}


def test_the_full_document_still_carries_what_the_fragment_strips(tmp_path: Path) -> None:
    """The counterpart: stripping is for `--merge` only, not a change to the real output."""

    out = tmp_path / "security-insights.yml"
    result = runner.invoke(app, ["emit-insights", "--target", str(tmp_path), "--output", str(out)])

    assert result.exit_code == 0, result.output
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert "last-updated" in doc["header"]


# --------------------------------------------------------------------------- #
# ingest-scorecard
# --------------------------------------------------------------------------- #


def test_a_scorecard_outside_the_target_tree_is_named_by_its_filename(tmp_path: Path) -> None:
    """`relative_to` cannot span trees, and an absolute path here would leak the home dir."""

    target = tmp_path / "repo"
    target.mkdir()
    elsewhere = tmp_path / "downloads" / "scorecard.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text("{}", encoding="utf-8")

    assert isc._display_path(elsewhere, target, None) == "scorecard.json"


def test_a_scorecard_inside_the_target_tree_is_named_by_its_relative_path(tmp_path: Path) -> None:
    inner = tmp_path / "evidence" / "scorecard.json"
    inner.parent.mkdir()
    inner.write_text("{}", encoding="utf-8")

    assert isc._display_path(inner, tmp_path, None) == "evidence/scorecard.json"


def test_the_path_the_operator_typed_wins_when_it_was_relative(tmp_path: Path) -> None:
    """Echoing their own argument back is the one form they are guaranteed to recognise."""

    chosen = tmp_path / "scorecard.json"
    chosen.write_text("{}", encoding="utf-8")

    assert isc._display_path(chosen, tmp_path, Path("./scorecard.json")) == "scorecard.json"


def test_an_oversized_scorecard_is_refused_before_it_is_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The ceiling exists so a hostile file is never handed to the JSON parser at all."""

    scorecard = tmp_path / "scorecard.json"
    scorecard.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(isc, "MAX_EVIDENCE_BYTES", 1)

    result = runner.invoke(app, ["ingest-scorecard", "--target", str(tmp_path), "--input", str(scorecard)])

    assert result.exit_code == 2, result.output
    assert "Scorecard JSON" in result.output
