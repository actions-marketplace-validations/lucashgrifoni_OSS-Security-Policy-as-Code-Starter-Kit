"""The parallel coverage data files must be ignored, and the check asks git rather than a regex.

`.gitignore` listed `.coverage` and stopped there. The two-step gate runs coverage twice and
leaves a batch of `.coverage.<hostname>.<pid>.<random>` files behind each time; 183 of them
were sitting untracked in the working tree when this was found, every one carrying the
machine name in its filename. They appeared in `git status`, so a single `git add -A` would
have committed the hostname 183 times, and `scripts/check_public_hygiene.py` walked all of
them on every run because it lists untracked-but-not-ignored files.

The names below are real ones taken from that tree, not invented: a pattern can match an
imagined filename and miss the one coverage actually writes. The assertions go through
`git check-ignore`, so a later edit that changes `.coverage.*` into something that no longer
matches fails here rather than silently restoring the leak.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]

#: Written by coverage's parallel mode. Kept verbatim from a real run.
_PARALLEL_DATA_FILES = (
    ".coverage.Lucas-PC.pid15712.XxvW6jOx.HUuVJ0ZM7Ffh",
    ".coverage.Lucas-PC.pid15944.XBlIIhgx.HThNnFO1050h",
    ".coverage.fv-az1024-19.pid1993.XmwNrXtx.HRlPnMh4gYsO",
)


def _is_ignored(name: str) -> bool:
    """True when git would ignore a file of this name at the repository root."""

    completed = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "check-ignore", "-q", "--no-index", name],
        capture_output=True,
        check=False,
    )
    assert completed.returncode in (0, 1), (
        f"git check-ignore failed for {name!r}: {completed.stderr.decode(errors='replace')!r}"
    )
    return completed.returncode == 0


@pytest.mark.parametrize("name", _PARALLEL_DATA_FILES)
def test_a_parallel_coverage_file_is_ignored(name: str) -> None:
    assert _is_ignored(name), (
        f"{name} would be tracked. Its name carries the machine that produced it, and a run "
        "of the gate writes a batch of them, so `git add -A` commits the hostname once per file."
    )


def test_the_single_coverage_file_is_still_ignored() -> None:
    """The pattern was added beside `.coverage`; neither may be lost while editing the other."""

    assert _is_ignored(".coverage")


def test_a_source_file_that_merely_starts_the_same_way_is_not_ignored() -> None:
    """The other half: a rule broad enough to swallow real files would be worse than the leak."""

    for name in ("coverage.py", "src/oss_policy_kit/coverage_report.py"):
        assert not _is_ignored(name), f"{name} is ignored, so the pattern is too broad"


def test_the_working_tree_has_no_untracked_coverage_data() -> None:
    """What the ignore rule is for, asserted against the tree this test runs in."""

    completed = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "ls-files", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
    )
    stray = [
        line
        for line in completed.stdout.decode(errors="replace").splitlines()
        if Path(line).name.startswith(".coverage.")
    ]
    assert not stray, f"{len(stray)} coverage data file(s) still reach `git status`, e.g. {stray[:3]}"
