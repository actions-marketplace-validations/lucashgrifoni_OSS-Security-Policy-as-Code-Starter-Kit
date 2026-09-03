"""A `git log` read line by line must terminate its last line, or that commit is dropped.

`git log --pretty=format:` is a SEPARATOR: it puts a newline BETWEEN entries and none after
the last one. A `while IFS= read -r` loop over that output reads the final line into the
variable and then returns non-zero at EOF, so the loop body never runs for it. The last
commit of the range disappears, silently, with the workflow green.

`--pretty=tformat:` -- and `--format=`, which is a shorthand for it -- is a TERMINATOR and
puts a newline after every entry, including the last.

This was not hypothetical. The release-notes workflow used the separator form, and the
published notes for v10.0.13, v10.0.14 and v10.0.15 are each missing the oldest commit in
their range. For v10.0.15 the dropped commit was the GL-PIPE-011 fix -- the change the
release is named after in its own tag annotation.

Reproduced before fixing: over the v10.0.16..v10.0.17 range, `git log` returned six subjects
and the loop produced five entries; with `tformat:` it produced six.
"""

from __future__ import annotations

import re

import pytest
import yaml

from tests.conftest import ROOT

_WORKFLOWS = ROOT / ".github" / "workflows"

#: The separator form, in both spellings git accepts.
_SEPARATOR_PRETTY = re.compile(r"--(?:pretty|format)=format:")

#: A shell loop that consumes its input one line at a time.
_LINE_LOOP = re.compile(r"while\b[^\n]*\bread\b")


def _scripts_reading_git_log_line_by_line() -> list[tuple[str, str]]:
    """(workflow, run script) for every step that pipes `git log` into a line loop."""

    found: list[tuple[str, str]] = []
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (document.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                script = str(step.get("run", ""))
                if "git log" in script and _LINE_LOOP.search(script):
                    found.append((path.name, script))
    return found


def test_some_workflow_still_reads_a_commit_list() -> None:
    """The assertion below would hold over an empty list, which proves nothing."""

    assert _scripts_reading_git_log_line_by_line(), (
        "no workflow reads `git log` line by line any more. If the release notes stopped "
        "being built from commits, this guard is watching something that no longer exists."
    )


@pytest.mark.parametrize(
    "workflow,script", _scripts_reading_git_log_line_by_line(), ids=lambda v: v if v.endswith(".yml") else ""
)
def test_the_commit_list_terminates_its_last_line(workflow: str, script: str) -> None:
    assert not _SEPARATOR_PRETTY.search(script), (
        f"{workflow} reads `git log` line by line but asks for the separator form of "
        "`--pretty`. That emits no newline after the final commit, so the loop silently "
        "drops it and the workflow stays green. Use `--pretty=tformat:` or `--format=`."
    )
