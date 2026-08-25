"""`evaluation-batch.md` must not report a passing gate over a batch it did not finish.

The JSON payload has been honest about this for a while: a repository that raised during
evaluation lands in `failed_directories`, separate from `skipped_directories`, and sets
`batch_complete: false` -- with a comment saying why, because "a consumer reading only
`gate_violated` would otherwise conclude the batch covered everything".

`_render_batch_markdown` was never given that list. Measured on a target root of three
repositories where one raises PermissionError:

    JSON      failed_directories: ['b-repo']   batch_complete: False
    Markdown  'b-repo' named anywhere: False
              the word 'failed':       False
              - **CI gate (`--fail-on: none`)**: **PASSED**

The only trace was `3 child folder(s) x 1 profile(s) = 2 run(s)` -- arithmetic a reader
has to do to notice a third of the target root is missing.

The run does exit 2, and that is a real mitigation while someone is watching the terminal.
The Markdown is the artifact that gets attached to a pull request and read later, with the
exit code long gone.

The caveat rides on the gate line rather than only in a section further down, because that
line is what a reader takes away, and both a PASSED and a VIOLATED gate over a partial
batch are partial.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import batch_evaluate
from oss_policy_kit.application.batch_evaluate import run_batch_evaluation

_REPOS = ("a-repo", "b-repo", "c-repo")
_UNREADABLE = "b-repo"

#: A child that is not a repository at all, so a real "Skipped directories" section exists
#: beside the failures and the two can be compared against each other rather than one of
#: them against an absent section.
_NOT_A_REPO = "notes"


def _target_root(tmp_path: Path) -> Path:
    mono = tmp_path / "mono"
    for name in _REPOS:
        child = mono / name
        child.mkdir(parents=True)
        (child / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (mono / _NOT_A_REPO).mkdir(parents=True)
    (mono / _NOT_A_REPO / "todo.txt").write_text("nothing to audit\n", encoding="utf-8")
    return mono


def _break_one_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make `b-repo` raise the way an unreadable directory does."""

    real = batch_evaluate.evaluate_repository

    def _evaluate(**kwargs: Any) -> Any:
        if Path(kwargs["repo_root"]).name == _UNREADABLE:
            raise PermissionError(13, "Permission denied")
        return real(**kwargs)

    monkeypatch.setattr(batch_evaluate, "evaluate_repository", _evaluate)


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch | None) -> tuple[str, dict[str, Any], Any]:
    if monkeypatch is not None:
        _break_one_repository(monkeypatch)
    out = tmp_path / "out"
    result = run_batch_evaluation(
        target_root=_target_root(tmp_path),
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        skip_non_repos=True,
    )
    return (
        (out / "evaluation-batch.md").read_text(encoding="utf-8"),
        json.loads((out / "evaluation-batch.json").read_text(encoding="utf-8")),
        result,
    )


def _section(markdown: str, title: str) -> str:
    """The body of one `## ` section, up to the next heading."""

    assert f"## {title}" in markdown, f"the report has no `## {title}` section"
    return markdown.split(f"## {title}", 1)[1].split("\n## ", 1)[0]


def test_the_gate_line_says_the_batch_was_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    markdown, payload, result = _run(tmp_path, monkeypatch)

    assert payload["failed_directories"], "the fixture did not produce a failure; nothing below is being tested"
    assert result.failed_count == 1

    gate_line = next(line for line in markdown.splitlines() if "CI gate" in line)
    assert "INCOMPLETE" in gate_line, (
        f"the gate line reads {gate_line!r} over a batch that evaluated two of three "
        "repositories. That line is what a reader takes away from the report."
    )
    assert f"1 of {len(_REPOS)}" in gate_line


def test_the_repository_that_could_not_be_evaluated_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    markdown, _payload, _result = _run(tmp_path, monkeypatch)

    assert "## Repositories that could not be evaluated" in markdown
    assert _UNREADABLE in markdown, "the report does not say which repository is missing from its totals"
    assert "Permission denied" in markdown


def test_a_failure_is_not_filed_under_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A skip means "not a repository"; a failure means "a repository we could not read".

    Merging them is what let a batch where every repository failed report a passing gate
    over zero runs, and the Markdown must keep the two apart the way the JSON does.
    """

    markdown, payload, _result = _run(tmp_path, monkeypatch)

    assert [s["name"] for s in payload["skipped_directories"]] == [_NOT_A_REPO], (
        "the fixture produced no skip, so this test would compare the failure against an "
        "absent section and assert nothing."
    )

    failures = _section(markdown, "Repositories that could not be evaluated")
    skipped = _section(markdown, "Skipped directories")

    assert _UNREADABLE in failures and _UNREADABLE not in skipped
    assert _NOT_A_REPO in skipped and _NOT_A_REPO not in failures


def test_a_complete_batch_says_nothing_about_being_incomplete(tmp_path: Path) -> None:
    """Otherwise the caveat would be printed on every run and mean nothing."""

    markdown, payload, result = _run(tmp_path, None)

    assert result.failed_count == 0
    assert "failed_directories" not in payload
    assert "INCOMPLETE" not in markdown
    assert "## Repositories that could not be evaluated" not in markdown

    gate_line = next(line for line in markdown.splitlines() if "CI gate" in line)
    assert gate_line.endswith("**PASSED**") or gate_line.endswith("**VIOLATED**"), (
        f"a complete batch carried a caveat on its gate line: {gate_line!r}"
    )


def test_the_markdown_does_not_leak_where_the_batch_ran(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The failure reason is built from `strerror`; the new section must not undo that.

    `str(OSError)` embeds the absolute filename, and this report ships in pull requests.
    """

    markdown, _payload, _result = _run(tmp_path, monkeypatch)

    assert str(tmp_path) not in markdown
    assert tmp_path.name not in markdown
