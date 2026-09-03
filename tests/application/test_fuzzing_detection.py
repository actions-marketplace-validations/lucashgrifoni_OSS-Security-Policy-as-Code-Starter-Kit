"""How the fuzzing control decides a repository actually fuzzes something.

Three independent signals, in descending order of confidence: an OpenSSF Scorecard Fuzzing
check scoring at least 7, a harness directory, a file named like a fuzz target, and a known
runner library mentioned in a source file. Each is a claim about the repository, so each has a
threshold, and the thresholds are what these tests hold.

The Scorecard path is the one worth being strict about: a Fuzzing check that exists but scores
below 7 is Scorecard saying it did *not* find fuzzing, and reading the check's presence as the
signal would turn every scanned repository into a fuzzing one.

The file walk is bounded the same way the webhook scan is -- noisy directories skipped, a file
cap, a byte cap per file, an unreadable file stepped over -- because it runs on every
`evaluate` against a clone of unknown size.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, ScorecardCheck
from oss_policy_kit.application import evaluators_fuzzing as fz


def _ctx(scorecard: Any = None) -> Any:
    return SimpleNamespace(scorecard=scorecard)


def _bundle(*checks: ScorecardCheck) -> ScorecardBundle:
    return ScorecardBundle(checks=list(checks), raw_path="scorecard.json")


def _file(root: Path, rel: str, body: str = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# The Scorecard signal
# --------------------------------------------------------------------------- #


def test_no_scorecard_is_not_a_fuzzing_signal() -> None:
    assert fz._scorecard_fuzzing_signal(_ctx()) == (False, None)


def test_a_scorecard_without_a_fuzzing_check_is_not_a_signal() -> None:
    """Absent is not the same as zero, and neither is a signal."""

    bundle = _bundle(ScorecardCheck(name="Branch-Protection", score=9))
    assert fz._scorecard_fuzzing_signal(_ctx(bundle)) == (False, None)


@pytest.mark.parametrize("score", [0, 6, None])
def test_a_fuzzing_check_below_the_threshold_is_not_a_signal(score: int | None) -> None:
    """A Fuzzing check scoring under 7 is Scorecard reporting it found none."""

    bundle = _bundle(ScorecardCheck(name="Fuzzing", score=score))
    matched, _reason = fz._scorecard_fuzzing_signal(_ctx(bundle))
    assert matched is False


@pytest.mark.parametrize("score", [7, 10])
def test_a_fuzzing_check_at_or_above_the_threshold_is_a_signal(score: int) -> None:
    bundle = _bundle(ScorecardCheck(name="Fuzzing", score=score))
    matched, reason = fz._scorecard_fuzzing_signal(_ctx(bundle))
    assert matched is True
    assert reason is not None
    assert str(score) in reason


# --------------------------------------------------------------------------- #
# Clone-side signals
# --------------------------------------------------------------------------- #


def test_a_populated_fuzz_directory_is_a_signal(tmp_path: Path) -> None:
    _file(tmp_path, "fuzz/fuzz_target.py")
    assert fz._has_fuzz_directory(tmp_path) is not None


def test_an_empty_fuzz_directory_is_not(tmp_path: Path) -> None:
    """A leftover empty folder is not a harness; requiring content is the point."""

    (tmp_path / "fuzz").mkdir()
    assert fz._has_fuzz_directory(tmp_path) is None


@pytest.mark.parametrize(
    "name",
    ["fuzz_target_parser.py", "fuzz_test_parser.go", "parser_fuzz.py", "parser_fuzz.go", "parser_fuzz.cc"],
)
def test_a_file_named_like_a_fuzz_target_is_a_signal(name: str, tmp_path: Path) -> None:
    """The hints are suffix- and prefix-shaped; a bare "fuzz" in the name is not enough."""

    _file(tmp_path, f"tests/{name}")
    found = fz._has_fuzz_filename(tmp_path)
    assert found is not None
    assert name in found


@pytest.mark.parametrize("name", ["test_parser.py", "fuzzy_matcher.py", "defuzz.txt"])
def test_a_filename_that_only_resembles_one_is_no_signal(name: str, tmp_path: Path) -> None:
    """`fuzzy_matcher.py` contains "fuzz" and has nothing to do with fuzzing."""

    _file(tmp_path, f"tests/{name}")
    assert fz._has_fuzz_filename(tmp_path) is None


def test_a_runner_library_in_a_source_file_is_a_signal(tmp_path: Path) -> None:
    _file(tmp_path, "tests/prop.py", "import atheris\n")
    found = fz._has_fuzz_content(tmp_path)
    assert found is not None
    assert "prop.py" in found


def test_a_runner_mention_in_an_unscanned_extension_is_ignored(tmp_path: Path) -> None:
    """Only source-shaped files are read; a mention in a changelog is not a harness."""

    _file(tmp_path, "CHANGELOG.md", "switched from atheris to something else")
    assert fz._has_fuzz_content(tmp_path) is None


def test_a_file_that_cannot_be_read_is_stepped_over(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reaching the unreadable file is asserted, not hoped for.

    The walk is sorted, so `a_locked.py` is read before `z_good.py` and the skip branch runs.
    The earlier version of this test asserted only the returned path, which is `z_good.py`
    in EITHER order -- so when the walk was still in filesystem order and Linux happened to
    yield the good file first, the test passed while the skip branch was never executed.
    Coverage was the only thing that noticed, months later, as an unexplained 99%. Recording
    the attempts makes an unordered walk fail here, by name.
    """

    _file(tmp_path, "a_locked.py", "import atheris\n")
    _file(tmp_path, "z_good.py", "import atheris\n")

    real_read_bytes = Path.read_bytes
    attempted: list[str] = []

    def _read_bytes(self: Path) -> bytes:
        attempted.append(self.name)
        if self.name == "a_locked.py":
            raise OSError(13, "Permission denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    found = fz._has_fuzz_content(tmp_path)
    assert found is not None
    assert "z_good.py" in found
    assert attempted[:2] == ["a_locked.py", "z_good.py"], (
        f"the scan read {attempted!r}. The unreadable file must be reached first, or this "
        "test passes without ever exercising the branch it exists for."
    )


# --------------------------------------------------------------------------- #
# The walk stays bounded
# --------------------------------------------------------------------------- #


def test_noisy_directories_are_skipped(tmp_path: Path) -> None:
    _file(tmp_path, "node_modules/pkg/fuzz_target.py")
    assert fz._has_fuzz_filename(tmp_path) is None


def test_the_walk_stops_at_the_file_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The cap is what keeps `evaluate` bounded on a clone of unknown size."""

    monkeypatch.setattr(fz, "_SCAN_FILE_LIMIT", 3)
    for i in range(10):
        _file(tmp_path, f"mod{i}.py")
    assert len(list(fz._iter_candidate_paths(tmp_path))) == 3


def test_an_entry_that_is_not_a_regular_file_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``os.walk`` lists broken symlinks, FIFOs and sockets among ``filenames``.

    Opening a FIFO blocks until a writer appears, so a repository containing one would hang
    the scan; ``is_file()`` is what keeps those out. Forced rather than built from a real
    FIFO or symlink, because ``os.mkfifo`` does not exist on Windows and ``os.symlink``
    needs a privilege there, and this branch should be covered wherever the suite runs.
    """

    _file(tmp_path, "regular.py", "x = 1")
    _file(tmp_path, "special.py", "y = 2")
    real_is_file = Path.is_file

    def _is_file(self: Path) -> bool:
        return False if self.name == "special.py" else real_is_file(self)

    monkeypatch.setattr(Path, "is_file", _is_file)
    assert [p.name for p in fz._iter_candidate_paths(tmp_path)] == ["regular.py"]


def test_a_tree_that_cannot_be_walked_yields_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_top: object) -> object:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(fz.os, "walk", _boom)
    assert list(fz._iter_candidate_paths(tmp_path)) == []
