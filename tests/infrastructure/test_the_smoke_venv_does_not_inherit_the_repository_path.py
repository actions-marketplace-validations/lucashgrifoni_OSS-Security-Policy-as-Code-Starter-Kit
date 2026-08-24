"""The consumer smoke venv must not inherit the repository's path length.

`scripts/consumer_smoke.py` is one of the canonical baseline commands, and playbook 05's consumer
campaign requires running it against paths with spaces and Unicode. On this checkout it does not
run at all:

    ERROR: Could not install packages due to an OSError: [Errno 2] No such file or directory:
    '...\\.consumer-smoke-venv\\Lib\\site-packages\\oss_policy_kit\\data\\schema\\
     evidence-github-environment-protection.schema.json'

`ENOENT` rather than `ENAMETOOLONG` is the Windows MAX_PATH symptom. Measured: repository root 143
characters, worst installed path 274, limit 260, `LongPathsEnabled` 0. The venv was anchored inside
the repository with no way to move it, so the script's ability to run depended on where the
adopter had cloned.

The obvious repair -- put the venv in a temp directory -- would have quietly removed a guard that
is there on purpose. `_remove_virtualenv` runs `shutil.rmtree`, and every path into it is forced
through `_resolve_repo_child`, which refuses anything outside the repository. Deleting that
containment to gain a shorter path trades a broken script for a dangerous one.

So containment is kept and its ROOT is parameterised: when the operator names a directory it must
still sit inside the repository, and when the script picks the location itself it creates the root
and confines deletion to that. The guard is not relaxed; it is pointed at whichever tree the venv
legitimately belongs to.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest
from scripts import consumer_smoke


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def test_the_default_venv_is_not_created_inside_the_repository(tmp_path: Path) -> None:
    """The reproduction, stated as a property: the repository's path must not bound the venv's."""

    repo_root = _repo(tmp_path)

    venv_dir, containment = consumer_smoke._resolve_smoke_venv(repo_root, None)
    try:
        assert not consumer_smoke._is_relative_to(venv_dir, repo_root), (
            "the venv is still anchored to the repository, so its path length follows the clone location"
        )
        assert consumer_smoke._is_relative_to(venv_dir, containment), "the venv escaped its own containment root"
    finally:
        shutil.rmtree(containment, ignore_errors=True)


def test_the_default_location_is_a_direct_child_of_the_systems_temporary_directory(tmp_path: Path) -> None:
    """Being "not in the repository" is not enough -- it has to be somewhere short and disposable.

    The assertion compares the PARENT, and that is the whole point of it. A first version asked
    only whether the root was somewhere under `tempfile.gettempdir()`, and a mutation restoring
    the repository anchoring sailed past: pytest's own `tmp_path` lives under the system temp
    directory too, so the check was true either way and measured nothing.
    """

    repo_root = _repo(tmp_path)

    venv_dir, containment = consumer_smoke._resolve_smoke_venv(repo_root, None)
    try:
        assert containment.parent == Path(tempfile.gettempdir()).resolve(), (
            f"the containment root is nested somewhere else entirely: {containment}"
        )
        assert consumer_smoke._is_relative_to(venv_dir, containment)
    finally:
        shutil.rmtree(containment, ignore_errors=True)


def test_two_repositories_at_different_depths_get_equally_short_venvs(tmp_path: Path) -> None:
    """The defect was that the venv path grew with the clone path. It must not any more."""

    shallow = _repo(tmp_path)
    deep = tmp_path / ("nested/" * 12).rstrip("/")
    deep.mkdir(parents=True)

    a_dir, a_root = consumer_smoke._resolve_smoke_venv(shallow, None)
    b_dir, b_root = consumer_smoke._resolve_smoke_venv(deep, None)
    try:
        assert len(str(a_dir)) == len(str(b_dir)), "the venv path still varies with the repository's depth"
    finally:
        shutil.rmtree(a_root, ignore_errors=True)
        shutil.rmtree(b_root, ignore_errors=True)


def test_a_directory_the_operator_names_still_has_to_live_in_the_repository(tmp_path: Path) -> None:
    """The containment guard is the reason this fix is not simply "use a temp directory".

    `_remove_virtualenv` deletes recursively. An operator-supplied path outside the repository is
    exactly what that guard exists to refuse, and parameterising the root must not soften it.
    """

    repo_root = _repo(tmp_path)
    outside = repo_root.parent / "outside-venv"

    with pytest.raises(SystemExit):
        consumer_smoke._resolve_smoke_venv(repo_root, outside)


def test_a_directory_the_operator_names_is_used_as_given(tmp_path: Path) -> None:
    """And the escape hatch has to actually work, or `--keep-venv` inspection loses its point."""

    repo_root = _repo(tmp_path)

    venv_dir, containment = consumer_smoke._resolve_smoke_venv(repo_root, Path("my-venv"))

    assert venv_dir == (repo_root / "my-venv").resolve()
    assert containment == repo_root


def test_the_cleanup_guard_still_refuses_a_directory_that_is_not_a_virtualenv(tmp_path: Path) -> None:
    """Unchanged behaviour, pinned here because this fix moves the root the guard is measured from."""

    repo_root = _repo(tmp_path)
    not_a_venv = repo_root / "not-a-venv"
    not_a_venv.mkdir()

    with pytest.raises(SystemExit):
        consumer_smoke._remove_virtualenv(repo_root, not_a_venv)

    assert not_a_venv.is_dir(), "the guard refused but deleted anyway"
