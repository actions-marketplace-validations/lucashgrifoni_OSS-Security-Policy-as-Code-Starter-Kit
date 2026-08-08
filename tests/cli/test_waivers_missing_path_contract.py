"""One unreadable `--waivers` path, three commands, two deliberate contracts (ADR-044).

`evaluate` and `correlate-findings` exit 2 when the path the operator typed cannot be read.
`emit-vex` warns and still writes the document. That difference is intended: a command whose
output asserts a *verdict* must stop, because verdicts computed without the waivers are
factually wrong; a command whose output is a *document* may continue, because a VEX carrying
`in_triage` on every finding states exactly what is true — these were not analysed.

Before this test the rule lived in a docstring inside `cli/emit_vex.py`. It was rediscovered
as `DEF-001` ("emit-vex should exit 2") and nearly implemented as a breaking change, which is
what an undocumented decision eventually costs. Asserting all three in one file makes the
asymmetry a contract a reader can find, and makes silent drift on either side fail.

A new command taking `--waivers` belongs in `_GATES` or `_DOCUMENTS` here, with the side chosen
on purpose rather than inherited from whichever command it was copied from.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_MISSING = "definitely-not-here.yaml"

_GOOD_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "osv-scanner",
                    "rules": [
                        {
                            "id": "CVE-2024-0001",
                            "shortDescription": {"text": "fixture"},
                            "fullDescription": {"text": "fixture for the waivers contract"},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "CVE-2024-0001",
                    "level": "error",
                    "message": {"text": "fixture"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "requirements.txt"}}}],
                }
            ],
        }
    ],
}


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={"COLUMNS": "200", "NO_COLOR": "1", "PYTHONIOENCODING": "utf-8", **_inherited()},
    )


def _inherited() -> dict[str, str]:
    import os

    # Keep PATH/SYSTEMROOT so the interpreter starts; drop nothing else that matters here.
    return {k: v for k, v in os.environ.items()}


def _lab(tmp_path: Path) -> Path:
    """A target that every command below can run against successfully."""

    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    sast = tmp_path / ".oss-policy-kit" / "evidence" / "sast"
    sast.mkdir(parents=True)
    (sast / "osv-scanner.sarif.json").write_text(json.dumps(_GOOD_SARIF), encoding="utf-8")
    return tmp_path


#: Commands whose output asserts a verdict. An unreadable --waivers must stop them.
#:
#: Every argv here is complete enough to succeed *without* `--waivers`, so an exit 2 can
#: only come from the flag under test. Dropping `--target` from `evaluate` made it exit 2
#: for a missing target instead — the same code for a different reason, which is the way
#: this kind of test quietly stops testing anything.
_GATES: tuple[tuple[str, list[str]], ...] = (
    ("evaluate", ["evaluate", "--target", ".", "--profile", "github-level-1", "--output-dir", "out", "--summary-only"]),
    ("correlate-findings", ["correlate-findings", "--target", ".", "--output", "findings.json"]),
)

#: Commands whose output is a document that can state its own incompleteness.
_DOCUMENTS: tuple[tuple[str, list[str]], ...] = (
    (
        "emit-vex",
        ["emit-vex", "--osv-sarif", ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json", "--output", "vex.json"],
    ),
)


@pytest.mark.parametrize(("name", "argv"), _GATES, ids=[n for n, _ in _GATES])
def test_a_gate_refuses_to_run_without_the_waivers_it_was_given(tmp_path: Path, name: str, argv: list[str]) -> None:
    lab = _lab(tmp_path)
    proc = _run([*argv, "--waivers", _MISSING], cwd=lab)

    assert proc.returncode == 2, (
        f"`{name}` produces a verdict, so an unreadable --waivers must stop it (exit 2). "
        f"Got {proc.returncode}. Running it anyway reports controls as failing that the "
        f"operator legitimately waived. See ADR-044.\nstderr={proc.stderr}"
    )
    assert "Traceback" not in proc.stderr
    assert _MISSING in proc.stderr, (
        "the error must name the path as typed so the operator can compare it against "
        f"their own command line.\nstderr={proc.stderr}"
    )


@pytest.mark.parametrize(("name", "argv"), _DOCUMENTS, ids=[n for n, _ in _DOCUMENTS])
def test_a_document_is_still_written_but_never_in_silence(tmp_path: Path, name: str, argv: list[str]) -> None:
    lab = _lab(tmp_path)
    proc = _run([*argv, "--waivers", _MISSING], cwd=lab)

    assert proc.returncode == 0, (
        f"`{name}` emits a document that states its own incompleteness, so an unreadable "
        f"--waivers warns rather than stops. Got {proc.returncode}. See ADR-044 before "
        f"changing this: exiting 2 here was considered and rejected.\nstderr={proc.stderr}"
    )
    assert "Waiver warning:" in proc.stderr.replace("\n", " "), (
        "the run may continue, but never silently — a typo'd path was once "
        f"indistinguishable from 'no waivers exist'.\nstderr={proc.stderr}"
    )
    assert (lab / "vex.json").is_file(), "the document must still be written"


def test_the_document_says_the_findings_were_not_analysed(tmp_path: Path) -> None:
    """What makes exit 0 defensible: the artifact does not claim more than it knows."""

    lab = _lab(tmp_path)
    proc = _run(
        [
            "emit-vex",
            "--osv-sarif",
            ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json",
            "--output",
            "vex.json",
            "--waivers",
            _MISSING,
        ],
        cwd=lab,
    )
    assert proc.returncode == 0, proc.stderr

    payload = json.loads((lab / "vex.json").read_text(encoding="utf-8"))
    states = {v["analysis"]["state"] for v in payload["vulnerabilities"]}
    assert states == {"in_triage"}, (
        "every finding must read as unanalysed when no waivers were applied. If this ever "
        "emitted `not_affected` without waivers, the document would assert something it "
        f"cannot know and exit 0 would stop being defensible. Got {states}."
    )
