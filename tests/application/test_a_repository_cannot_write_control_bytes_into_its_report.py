"""The audited repository must not decide what its own security report appears to say.

`CI-LEAST-009` interpolates a workflow's job NAME into its reason, and a job name is a
YAML key the target chooses. A workflow declaring `"build\\e[31m INJECTED \\e[0m\\a"` is a
legal document -- the file holds the printable escape and YAML decodes it -- and no plugin
or custom profile is involved: this is a bundled control on `github-level-1`.

Measured before the fix, on the real CLI:

    evaluation-report.md   ESC present: True   BEL present: True

That file is `cat`-ed, pasted into pull requests, and attached to releases. An escape
there colours the line, moves the cursor, or with `\\e[2K\\r` overwrites what was already
printed.

The format characters are the sharper half and reached BOTH artifacts:

    RLO (U+202E) raw in markdown: True    raw in json: True
    ZWSP (U+200B) raw in markdown: True   raw in json: True

`json.dumps` escapes C0 controls, which is why the ANSI case looked contained in the JSON
-- but under `ensure_ascii=False` it writes every other category through, so the
right-to-left override that reverses displayed text landed in the JSON verbatim.

Cleaning happens in `ControlResult`, not at the writers: JSON, Markdown, SARIF and the
terminal all render from that one object, so a fifth writer cannot arrive unprotected.

What is deliberately kept is asserted too: the VISIBLE characters of the payload survive,
so the reader sees exactly the text that was there minus the characters that have no
glyph -- the report does not quietly rewrite what the repository wrote.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from oss_policy_kit.application.reporting import _md_cell
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.models import ControlResult, ControlStatus, without_control_characters

runner = CliRunner()

_ESC = "\x1b"
_BEL = "\x07"
_RLO = "‮"  # RIGHT-TO-LEFT OVERRIDE -- the Trojan Source character
_ZWSP = "​"


def _repo_with_job_named(tmp_path: Path, job_name: str) -> Path:
    """A repository whose only workflow trips CI-LEAST-009 under the given job name."""

    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")

    document = {
        "name": "ci",
        "on": ["push"],
        "jobs": {
            job_name: {
                "runs-on": "ubuntu-latest",
                # A non-default token with no `permissions:` mapping is what the control fires on.
                "steps": [{"uses": "actions/checkout@v4", "with": {"token": "${{ secrets.MY_PAT }}"}}],
            }
        },
    }
    workflow = repo / ".github" / "workflows" / "ci.yml"
    workflow.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")

    # The fixture verifies itself: PyYAML refuses raw control bytes in the STREAM, so the
    # file has to carry the printable escape and decode back to the real character. If the
    # emitter ever stopped doing that, the assertions below would pass over a payload that
    # was never dangerous.
    reloaded = next(iter(yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]))
    assert reloaded == job_name, f"the workflow did not round-trip the job name: {reloaded!r}"
    return repo


def _evaluate(repo: Path, out: Path) -> tuple[str, str]:
    result = runner.invoke(
        app, ["evaluate", "--target", str(repo), "--profile", "github-level-1", "--output-dir", str(out)]
    )
    assert result.exit_code in (0, 1), f"exit {result.exit_code}: {result.output[-400:]!r}"
    return (
        (out / "evaluation-report.md").read_text(encoding="utf-8"),
        (out / "evaluation-report.json").read_text(encoding="utf-8"),
    )


def test_an_ansi_escape_from_a_job_name_does_not_reach_the_shareable_report(tmp_path: Path) -> None:
    payload = "build" + _ESC + "[31m INJECTED " + _ESC + "[0m" + _BEL
    markdown, raw_json = _evaluate(_repo_with_job_named(tmp_path, payload), tmp_path / "out")

    assert "INJECTED" in markdown, (
        "the control did not fire, so this test proves nothing. It needs a job that trips "
        "CI-LEAST-009 for the job name to reach the report at all."
    )
    assert _ESC not in markdown, "an ANSI escape reached evaluation-report.md"
    assert _BEL not in markdown
    assert _ESC not in raw_json


def test_the_visible_characters_of_the_payload_are_kept(tmp_path: Path) -> None:
    """Nothing is rewritten beyond dropping what has no glyph.

    A report that silently edited the repository's own strings would be a different kind of
    dishonest, so the reader gets exactly what was written minus the invisible characters.
    """

    payload = "build" + _ESC + "[31m INJECTED " + _ESC + "[0m"
    markdown, _json = _evaluate(_repo_with_job_named(tmp_path, payload), tmp_path / "out")

    assert "build[31m INJECTED [0m" in markdown


@pytest.mark.parametrize("invisible", [_RLO, _ZWSP], ids=["right-to-left-override", "zero-width-space"])
def test_a_format_character_reaches_neither_artifact(invisible: str, tmp_path: Path) -> None:
    """The half `json.dumps` does not escape, so the JSON carried it raw."""

    markdown, raw_json = _evaluate(_repo_with_job_named(tmp_path, "build" + invisible + "dessap"), tmp_path / "out")

    assert invisible not in markdown, "an invisible character reached evaluation-report.md"
    assert invisible not in raw_json, (
        "an invisible character reached evaluation-report.json. `ensure_ascii=False` writes "
        "every category except the C0 controls straight through."
    )
    assert "builddessap" in json.loads(raw_json)["controls"][0]["message"] or "builddessap" in raw_json


def test_whitespace_survives() -> None:
    """Tab, newline and carriage return are whitespace; the Markdown writer folds them itself."""

    assert without_control_characters("a\tb\nc\rd") == "a\tb\nc\rd"


def test_ordinary_text_is_returned_unchanged() -> None:
    assert without_control_characters("Broad permissions in build.yml (deploy)") == (
        "Broad permissions in build.yml (deploy)"
    )
    assert without_control_characters("acentuação 中文 🔐") == "acentuação 中文 🔐"


def test_the_result_object_cleans_its_own_prose() -> None:
    """Built directly, with no evaluator or writer in the way."""

    result = ControlResult(
        control_id="X-1",
        title="t" + _ESC + "itle",
        category="ci_cd",
        status=ControlStatus.FAIL,
        profile="p",
        evidence_sources=[],
        confidence="low",
        reason="re" + _RLO + "ason",
        remediation="rem" + _ZWSP + "ediation",
    )

    assert (result.title, result.reason, result.remediation) == ("title", "reason", "remediation")


def test_the_markdown_cell_still_does_its_structural_job() -> None:
    """Unchanged: a pipe would split the row and shift every later value under a wrong header."""

    assert _md_cell("a|b") == "a\\|b"
    assert _md_cell("a\r\nb") == "a b"
    assert _md_cell("a\nb") == "a b"
    assert _md_cell("a\rb") == "a b"


def test_the_markdown_cell_also_cleans_values_that_bypass_the_result_object() -> None:
    """The waiver owner and an external profile's category strings arrive here directly."""

    assert _md_cell("own" + _ESC + "[31mer") == "own[31mer"
