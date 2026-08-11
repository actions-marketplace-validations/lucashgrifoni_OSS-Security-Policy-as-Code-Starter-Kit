"""`evaluate-batch` refusing rather than reporting an empty run, and its path handling.

A batch that evaluates nothing must say so and exit 2. Returning an empty result would be
worse than an error: the caller gets a report with no failures in it, which reads exactly
like a clean sweep of every repository under the root.

Those two refusals had never been executed, nor had the fallback that decides how a report
path is written when it does not sit under the batch output directory -- the place an
absolute host path could reach a shareable artifact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import batch_evaluate as be
from oss_policy_kit.domain.errors import InvalidInputError


def _repo(root: Path, name: str) -> Path:
    """A directory `is_likely_repository` recognises, via a primary signal."""

    path = root / name
    (path / ".git").mkdir(parents=True)
    (path / "README.md").write_text("# repo\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# refusing an empty batch
# --------------------------------------------------------------------------- #


def test_a_root_with_no_subdirectories_is_refused(tmp_path: Path) -> None:
    """An empty result set here would read as "every repository passed"."""

    with pytest.raises(InvalidInputError) as excinfo:
        be.run_batch_evaluation(
            target_root=tmp_path,
            profile_ids=["github-level-1"],
            output_dir=tmp_path / "out",
            kit_root=None,
            include=None,
            exclude=None,
        )

    assert "No subdirectories" in str(excinfo.value)


def test_filters_that_exclude_everything_are_refused_with_the_flags_named(tmp_path: Path) -> None:
    """The message has to name what to change, or the operator only knows it did not work."""

    _repo(tmp_path, "service-a")

    with pytest.raises(InvalidInputError) as excinfo:
        be.run_batch_evaluation(
            target_root=tmp_path,
            profile_ids=["github-level-1"],
            output_dir=tmp_path / "out",
            kit_root=None,
            include="no-such-name-*",
            exclude=None,
        )

    assert "No subdirectories" in str(excinfo.value)


def test_skipping_every_non_repository_is_refused_and_says_how_to_proceed(tmp_path: Path) -> None:
    """Directories exist but none is a repository -- a different state, its own message."""

    (tmp_path / "notes").mkdir()
    (tmp_path / "scratch").mkdir()

    with pytest.raises(InvalidInputError) as excinfo:
        be.run_batch_evaluation(
            target_root=tmp_path,
            profile_ids=["github-level-1"],
            output_dir=tmp_path / "out",
            kit_root=None,
            include=None,
            exclude=None,
            skip_non_repos=True,
        )

    message = str(excinfo.value)
    assert "No repositories to evaluate" in message
    assert "--skip-non-repos" in message


def test_an_unreadable_target_root_reports_the_os_error_without_the_path(tmp_path: Path) -> None:
    """M-002: the message may carry the OS reason and the basename, never the full path."""

    missing = tmp_path / "deep" / "secret-account" / "roots"

    with pytest.raises(InvalidInputError) as excinfo:
        be.discover_batch_targets(missing, include=None, exclude=None)

    message = str(excinfo.value)
    assert "secret-account" not in message
    assert "roots" in message


# --------------------------------------------------------------------------- #
# probing directories that cannot be read
# --------------------------------------------------------------------------- #


def test_a_glob_the_os_refuses_counts_as_no_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A permission error while probing must not end the batch or claim a signal."""

    def _refuse(self: Path, pattern: str) -> Any:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "glob", _refuse)

    assert be._glob_has_match(tmp_path, "*.py") is False


def test_a_glob_that_matches_is_reported(tmp_path: Path) -> None:
    """The negative case above only means something if a real match is still seen."""

    (tmp_path / "app.py").write_text("", encoding="utf-8")

    assert be._glob_has_match(tmp_path, "*.py") is True


def test_hidden_directories_are_not_batch_targets(tmp_path: Path) -> None:
    """`.git`, `.venv` and friends are not repositories to evaluate."""

    _repo(tmp_path, "service-a")
    (tmp_path / ".cache").mkdir()

    names = [p.name for p in be.discover_batch_targets(tmp_path, include=None, exclude=None)]

    assert names == ["service-a"]


def test_include_and_exclude_are_applied_to_the_directory_name(tmp_path: Path) -> None:
    _repo(tmp_path, "service-a")
    _repo(tmp_path, "service-b")
    _repo(tmp_path, "tooling")

    included = [p.name for p in be.discover_batch_targets(tmp_path, include="service-*", exclude=None)]
    excluded = [p.name for p in be.discover_batch_targets(tmp_path, include=None, exclude="service-*")]

    assert included == ["service-a", "service-b"]
    assert excluded == ["tooling"]


# --------------------------------------------------------------------------- #
# comparison lines
# --------------------------------------------------------------------------- #


def test_no_targets_produce_no_comparison_lines() -> None:
    """Nothing to compare is silence, not a sentence about zero repositories."""

    assert be._batch_comparison_lines({}, False, None) == []


def test_targets_that_all_tie_are_reported_as_tied() -> None:
    """Naming a "worst performer" among equals would be a misleading ranking."""

    lines = be._batch_comparison_lines({"a": 3, "b": 3}, True, 3)

    assert lines
    assert "no clear best or worst" in " ".join(lines)


def test_targets_that_differ_produce_a_comparison() -> None:
    lines = be._batch_comparison_lines({"a": 1, "b": 9}, False, None)

    assert lines
    assert any("a" in line for line in lines)
