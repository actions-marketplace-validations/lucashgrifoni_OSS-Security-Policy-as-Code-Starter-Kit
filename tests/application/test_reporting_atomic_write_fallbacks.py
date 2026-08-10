"""The fallbacks inside the atomic report write, on the branches that only fire when it fails.

Reports are staged to a temp file and renamed into place so an interrupted write cannot
leave a torn `evaluation-report.json` behind. The happy path is well covered. The branches
that decide what to do when *staging itself* fails were not, and they are the ones holding
the guarantee: each has to either preserve atomicity or fail loudly, and never quietly
degrade to a truncating in-place write.

One of them is load-bearing in a way that looks like a no-op. `FileExistsError` is an
`OSError`, so the bare `raise` that re-raises it exists to stop a blocked temp name from
falling into the path-length fallback below and writing the destination in place -- which
is exactly the bypass the exclusive create was added to refuse. A test that only checked
"an error propagates" would not notice if that clause were deleted.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import reporting as rp

# --------------------------------------------------------------------------- #
# staging
# --------------------------------------------------------------------------- #


def test_a_blocked_temp_name_refuses_rather_than_writing_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exclusive create exists to refuse; falling through would defeat it."""

    dest = tmp_path / "evaluation-report.json"
    dest.write_text("previous", encoding="utf-8")

    def _always_taken(_tmp: Path, _text: str) -> None:
        raise FileExistsError(errno.EEXIST, "File exists")

    monkeypatch.setattr(rp, "_create_temp_exclusive", _always_taken)

    with pytest.raises(FileExistsError):
        rp._stage_text(dest, "new content")

    assert dest.read_text(encoding="utf-8") == "previous", "the destination was written in place"


def _refuse_with(errno_: int) -> Any:
    def _fail(_tmp: Path, _text: str) -> None:
        raise OSError(errno_, os.strerror(errno_))

    return _fail


def test_an_ordinary_destination_degrades_to_an_in_place_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The temp name adds 13 characters, so length can plausibly be what failed.

    Writing in place is non-atomic but is strictly what the caller had before the temp
    file existed, so it is the documented fallback rather than a lost report. It is
    signalled by returning None: there is nothing left to publish.
    """

    dest = tmp_path / "evaluation-report.json"
    dest.write_text("previous", encoding="utf-8")
    monkeypatch.setattr(rp, "_create_temp_exclusive", _refuse_with(errno.ENAMETOOLONG))

    assert rp._stage_text(dest, "new content") is None
    assert dest.read_text(encoding="utf-8") == "new content"


def test_a_failure_on_a_shorter_temp_path_is_raised_not_worked_around(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Once the temp name is the SHORT form, it is no longer than the destination.

    Length cannot be what failed, so degrading to an in-place write would trade
    atomicity for nothing and hide a real ENOSPC / EACCES. Reached by a destination
    long enough to push the long temp name past the path budget, which is what selects
    the short form. Nothing touches the filesystem on this branch, so the path only has
    to be long, not creatable.
    """

    deep = tmp_path
    while len(str(deep)) < 200:
        deep = deep / "nested-directory-segment"
    dest = deep / "evaluation-report-with-a-long-name.json"
    assert len(str(dest.with_name(f".{dest.name}.deadbeef.tmp"))) > rp._MAX_TEMP_PATH, (
        "fixture does not select the short temp-name form"
    )

    monkeypatch.setattr(rp, "_create_temp_exclusive", _refuse_with(errno.ENOSPC))

    with pytest.raises(OSError) as excinfo:
        rp._stage_text(dest, "new content")

    assert excinfo.value.errno == errno.ENOSPC


def test_an_interrupt_during_staging_leaves_no_temp_file_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A KeyboardInterrupt is not an OSError; the cleanup has to catch BaseException."""

    dest = tmp_path / "evaluation-report.json"

    def _interrupted(tmp: Path, _text: str) -> None:
        tmp.write_text("half", encoding="utf-8")
        raise KeyboardInterrupt

    monkeypatch.setattr(rp, "_create_temp_exclusive", _interrupted)

    with pytest.raises(KeyboardInterrupt):
        rp._stage_text(dest, "new content")

    assert list(tmp_path.iterdir()) == [], "a temp file was orphaned"


def test_a_successful_stage_returns_a_temp_file_and_does_not_touch_the_destination(
    tmp_path: Path,
) -> None:
    """The positive case, so the refusals above cannot pass by never staging anything."""

    dest = tmp_path / "evaluation-report.json"
    dest.write_text("previous", encoding="utf-8")

    tmp = rp._stage_text(dest, "new content")

    assert tmp is not None
    assert tmp.read_text(encoding="utf-8") == "new content"
    assert dest.read_text(encoding="utf-8") == "previous"
    rp._discard_staged(tmp)


# --------------------------------------------------------------------------- #
# publishing
# --------------------------------------------------------------------------- #


def test_publishing_nothing_is_a_no_op(tmp_path: Path) -> None:
    """`tmp is None` means the fallback already wrote the destination."""

    dest = tmp_path / "evaluation-report.json"
    dest.write_text("written by the fallback", encoding="utf-8")

    rp._publish_staged(None, dest, "ignored")

    assert dest.read_text(encoding="utf-8") == "written by the fallback"


def test_publishing_swaps_the_staged_file_into_place(tmp_path: Path) -> None:
    dest = tmp_path / "evaluation-report.json"
    dest.write_text("previous", encoding="utf-8")
    tmp = rp._stage_text(dest, "new content")

    rp._publish_staged(tmp, dest, "new content")

    assert dest.read_text(encoding="utf-8") == "new content"
    assert sorted(p.name for p in tmp_path.iterdir()) == [dest.name], "a temp file survived the swap"


def test_a_non_sharing_failure_during_the_swap_cleans_up_and_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ENOSPC on the rename is a real failure; it must not leave the temp file behind."""

    dest = tmp_path / "evaluation-report.json"
    dest.write_text("previous", encoding="utf-8")
    tmp = rp._stage_text(dest, "new content")

    def _boom(src: Any, dst: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "replace", _boom)

    with pytest.raises(OSError):
        rp._publish_staged(tmp, dest, "new content")

    assert dest.read_text(encoding="utf-8") == "previous"
    assert sorted(p.name for p in tmp_path.iterdir()) == [dest.name], "a temp file was orphaned"


# --------------------------------------------------------------------------- #
# rollback
# --------------------------------------------------------------------------- #


def test_a_prior_that_was_not_restorable_reports_failure_without_touching_anything(
    tmp_path: Path,
) -> None:
    """Claiming a rollback that did not happen is worse than reporting it failed."""

    dest = tmp_path / "evaluation-report.json"
    dest.write_text("current", encoding="utf-8")

    restored = rp._restore_prior_content(dest, rp._PriorContent(restorable=False, data=None))

    assert restored is False
    assert dest.read_text(encoding="utf-8") == "current"


def test_rolling_back_to_no_file_removes_the_destination(tmp_path: Path) -> None:
    """`data is None` means the destination did not exist before; rollback deletes it."""

    dest = tmp_path / "evaluation-report.json"
    dest.write_text("written by the run being rolled back", encoding="utf-8")

    restored = rp._restore_prior_content(dest, rp._PriorContent(restorable=True, data=None))

    assert restored is True
    assert not dest.exists()


def test_a_removal_the_os_refuses_reports_failure_rather_than_claiming_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "evaluation-report.json"
    dest.write_text("current", encoding="utf-8")

    def _refuse(self: Path, missing_ok: bool = False) -> None:
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(Path, "unlink", _refuse)

    assert rp._restore_prior_content(dest, rp._PriorContent(restorable=True, data=None)) is False


# --------------------------------------------------------------------------- #
# small classifiers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("token", ["/etc/passwd", "C:\\repo", "\\\\server\\share", "~/repo"])
def test_rooted_looking_tokens_are_recognized(token: str) -> None:
    assert rp._looks_like_rooted_path(token) is True


@pytest.mark.parametrize("token", ["src/app.py", ".github/workflows/ci.yml", "README.md", ""])
def test_relative_tokens_are_not_rooted(token: str) -> None:
    assert rp._looks_like_rooted_path(token) is False


@pytest.mark.parametrize(
    ("profile_id", "family"),
    [
        ("github-level-1", "github"),
        ("gitlab-level-2", "gitlab"),
        ("azure-level-1", "azure"),
        ("aws-release-hardening-2", "aws"),
    ],
)
def test_a_profile_id_resolves_to_its_platform_family(profile_id: str, family: str) -> None:
    assert rp._profile_family(profile_id) == family


def test_an_unrecognized_profile_id_has_no_family() -> None:
    """A family guess on an unknown id would mislabel the whole report section."""

    assert rp._profile_family("something-custom-1") is None
