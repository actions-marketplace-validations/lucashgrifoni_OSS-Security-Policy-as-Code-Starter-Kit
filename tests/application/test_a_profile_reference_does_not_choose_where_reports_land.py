"""A profile reference must not decide where a batch writes, or whether targets share a file.

`evaluate-many` writes each run to ``output_dir / <target> / <profile>``. The target name was
reduced to a safe component; the profile reference was pasted in raw, and `pathlib` resolves
whatever it is handed.

Reproduced through the CLI with three targets before fixing it:

    -p ../profile.yaml     ->  output_dir/<target>/../profile.yaml
                               collapses to output_dir/profile.yaml -- the target component
                               disappears, all three targets write the SAME file, and the one
                               that survives holds the LAST target's verdict.
                               evaluation-batch.json still declared three runs with three
                               report links. Exit 0.

    -p ../../profile.yaml  ->  walks out of --output-dir entirely. Zero reports where the
                               operator asked, one written beside it, exit 0. The path in the
                               batch artifact is basename-sanitized for privacy, so it does not
                               even say where they went.

A third shape aborted with "Cannot write to --output-dir" when the escaped destination hit an
existing file, sending the operator to investigate a directory that was perfectly fine.

Both halves of the destination now go through one sanitizer. Two different sanitizers on the
same path is how this happened.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from tests.conftest import EXAMPLE_VULNERABLE, ROOT

from oss_policy_kit.application.batch_evaluate import _safe_component, run_batch_evaluation

_BUNDLED_PROFILE = ROOT / "src" / "oss_policy_kit" / "data" / "profiles" / "github-level-1" / "profile.yaml"
_TARGETS = ("a-repo", "b-repo", "c-repo")


def _lab(tmp_path: Path) -> tuple[Path, Path]:
    """A batch root with three targets, and an external profile above it."""

    mono = tmp_path / "mono"
    for name in _TARGETS:
        shutil.copytree(EXAMPLE_VULNERABLE, mono / name)
    shutil.copy(_BUNDLED_PROFILE, tmp_path / "profile.yaml")
    return mono, tmp_path / "out"


def test_every_target_keeps_its_own_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Three targets must produce three verdicts, not one file written three times."""

    mono, out = _lab(tmp_path)
    monkeypatch.chdir(mono)

    run_batch_evaluation(
        target_root=mono,
        profile_ids=["../profile.yaml"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )

    reports = sorted(out.rglob("evaluation-report.json"))
    assert len(reports) == len(_TARGETS), (
        f"{len(reports)} report(s) for {len(_TARGETS)} targets. A profile reference containing "
        "`..` collapsed the target component, so the targets overwrote each other and only the "
        f"last verdict survived: {[str(p.relative_to(out)) for p in reports]}"
    )

    written_for = {json.loads(p.read_text(encoding="utf-8"))["target_path"] for p in reports}
    assert written_for == set(_TARGETS), (
        f"the surviving reports describe {sorted(written_for)}, not {sorted(_TARGETS)}. A verdict "
        "that was computed and then overwritten is worse than one that was never computed: the "
        "batch summary still counts it."
    )


def test_no_report_is_written_outside_the_requested_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`--output-dir` is a boundary, and a profile reference must not be able to cross it.

    The escape needs the working directory and ``output_dir/<target>`` to sit at different
    depths, because the SAME reference is resolved from both: once to find the profile, once
    to build the destination. That asymmetry is the defect in one sentence, so the layout
    below deliberately reproduces it -- `out` one level deeper, the working directory one
    level lower, and `../..` therefore landing outside `out` while still finding the profile.
    """

    mono, _unused = _lab(tmp_path)
    out = tmp_path / "reports" / "out"
    monkeypatch.chdir(mono / _TARGETS[0])

    run_batch_evaluation(
        target_root=mono,
        profile_ids=["../../profile.yaml"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )

    escaped = [p for p in tmp_path.rglob("evaluation-report.json") if out not in p.parents]
    assert not escaped, (
        "reports were written outside --output-dir: "
        f"{[str(p.relative_to(tmp_path)) for p in escaped]}. The run still exits 0, and the path "
        "recorded in evaluation-batch.json is basename-sanitized, so nothing tells the operator "
        "where their reports went."
    )


def test_a_bundled_profile_id_still_names_its_own_directory(tmp_path: Path) -> None:
    """The sanitizer must not disturb the ordinary case, which is every normal invocation."""

    mono, out = _lab(tmp_path)

    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
    )

    for name in _TARGETS:
        assert (out / name / "github-level-1" / "evaluation-report.json").is_file(), (
            f"{name}/github-level-1/evaluation-report.json is missing; sanitizing the profile "
            "reference changed where an ordinary bundled profile writes."
        )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("github-level-1", "github-level-1", id="a-bundled-id-is-left-alone"),
        pytest.param("../profile.yaml", ".._profile.yaml", id="separators-are-flattened"),
        pytest.param(r"a/b\c", "a_b_c", id="both-separators-are-flattened"),
        pytest.param("..", "_", id="dot-dot-alone-traverses-without-a-separator"),
        pytest.param(".", "_", id="a-single-dot-is-the-directory-itself"),
        pytest.param("...", "_", id="any-all-dot-component"),
        pytest.param("", "_", id="an-empty-component-would-vanish"),
    ],
)
def test_a_component_can_never_traverse_or_disappear(raw: str, expected: str) -> None:
    """The dot cases are the ones flattening separators does not cover.

    `.` and `..` carry no separator and still move the destination, and an empty result would
    drop the component entirely -- which is precisely the failure this sanitizer exists to
    stop. A mutation reducing the function to a separator replacement passed every
    behavioural test above, so these are asserted directly rather than inferred from a run.
    """

    assert _safe_component(raw) == expected
