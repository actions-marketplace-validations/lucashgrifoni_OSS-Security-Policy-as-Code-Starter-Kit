"""Two scanners that walk a user-supplied tree, and what they do with what they find there.

The webhook evaluator reads source files looking for three signals -- a route, a signature
check, a replay defence. Everything about that walk is bounded on purpose: it skips vendor
directories, only reads known source extensions, caps how many files it opens and how much of
each it reads, and stops as soon as all three signals are found. Those bounds are the reason
`evaluate` finishes on a large monorepo, and none of them was covered.

`_load_profiles` in the catalog differ has the opposite job: it must tolerate whatever a
`--from` snapshot contains, because that directory is as untrusted as any other input. A
directory with no `profile.yaml`, or a `profile.yaml` that parses to a list instead of a
mapping, has to be skipped rather than crash a diff of the other fifty profiles.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application import catalog_diff as cd
from oss_policy_kit.application import evaluators_webhook as wh


def _source(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# The bounded walk
# --------------------------------------------------------------------------- #


def test_vendor_directories_are_not_walked(tmp_path: Path) -> None:
    """A hint inside node_modules is somebody else's code, not this repository's posture."""

    _source(tmp_path, "node_modules/pkg/index.js", "app.post('/webhook', verifySignature)")
    assert list(wh._iter_candidate_paths(tmp_path)) == []


def test_only_known_source_extensions_are_read(tmp_path: Path) -> None:
    _source(tmp_path, "notes.bin", "x-hub-signature-256")
    _source(tmp_path, "app.py", "print('hi')")
    found = [p.name for p in wh._iter_candidate_paths(tmp_path)]
    assert found == ["app.py"], found


def test_the_walk_stops_at_the_file_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The cap is why `evaluate` finishes on a monorepo; without it the scan is unbounded."""

    monkeypatch.setattr(wh, "_SCAN_FILE_LIMIT", 3)
    for i in range(10):
        _source(tmp_path, f"mod{i}.py", "x = 1")
    assert len(list(wh._iter_candidate_paths(tmp_path))) == 3


def test_a_tree_that_cannot_be_walked_yields_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A permission error mid-walk ends the scan; it must not escape into the evaluator."""

    def _boom(_top: object) -> object:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(wh.os, "walk", _boom)
    assert list(wh._iter_candidate_paths(tmp_path)) == []


def test_a_file_that_cannot_be_read_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """One unreadable file must not hide the signals in the readable ones beside it.

    The attempt on the unreadable file is asserted rather than assumed: the returned hint is
    `routes.py` whichever order the walk uses, so without this the test cannot tell an
    exercised skip branch from a walk that never reached the locked file.
    """

    _source(tmp_path, "locked.py", "x-hub-signature-256")
    _source(tmp_path, "routes.py", "@app.post('/webhook')")

    real_read_bytes = Path.read_bytes
    attempted: list[str] = []

    def _read_bytes(self: Path) -> bytes:
        attempted.append(self.name)
        if self.name == "locked.py":
            raise OSError(13, "Permission denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    has_route, route_hint, _sig, _sh, _replay, _rh = wh._scan_signals(tmp_path)
    assert has_route is True
    assert route_hint == "routes.py"
    assert attempted == ["locked.py", "routes.py"], (
        f"the scan read {attempted!r}; the unreadable file was not reached first"
    )


def test_the_scan_stops_once_all_three_signals_are_found(tmp_path: Path) -> None:
    """No reason to keep reading; the early exit is what keeps a large clone cheap."""

    _source(
        tmp_path,
        "webhook.py",
        "@app.post('/webhook')\nx-hub-signature-256\nidempotency-key\n",
    )
    for i in range(5):
        _source(tmp_path, f"filler{i}.py", "nothing here")

    has_route, _rh, has_sig, _sh, has_replay, _ph = wh._scan_signals(tmp_path)
    assert has_route
    assert has_sig
    assert has_replay


def test_scan_for_any_skips_an_unreadable_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`z_good.py` is the answer in either walk order, so the attempts are what is asserted."""

    _source(tmp_path, "a_locked.py", "cosign")
    _source(tmp_path, "z_good.py", "cosign verify-blob")

    real_read_bytes = Path.read_bytes
    attempted: list[str] = []

    def _read_bytes(self: Path) -> bytes:
        attempted.append(self.name)
        if self.name == "a_locked.py":
            raise OSError(13, "Permission denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    assert wh._scan_for_any(tmp_path, ("cosign",)) == "z_good.py"
    assert attempted == ["a_locked.py", "z_good.py"], (
        f"the scan read {attempted!r}; the unreadable file was not reached first"
    )


def test_scan_for_any_returns_nothing_when_no_hint_matches(tmp_path: Path) -> None:
    _source(tmp_path, "app.py", "print('hi')")
    assert wh._scan_for_any(tmp_path, ("cosign",)) is None


# --------------------------------------------------------------------------- #
# Tolerating a historical snapshot
# --------------------------------------------------------------------------- #


def test_a_directory_without_a_profile_file_is_skipped(tmp_path: Path) -> None:
    """`--from` can point at any directory; a stray subfolder must not fail the diff."""

    (tmp_path / "not-a-profile").mkdir()
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "profile.yaml").write_text("id: p1\ncontrols: [A, B]\n", encoding="utf-8")

    assert cd._load_profiles(tmp_path) == {"p1": ("A", "B")}


def test_a_profile_yaml_that_is_not_a_mapping_is_skipped(tmp_path: Path) -> None:
    """A list where a mapping was expected is a broken snapshot, not a reason to crash."""

    (tmp_path / "broken").mkdir()
    (tmp_path / "broken" / "profile.yaml").write_text("- one\n- two\n", encoding="utf-8")
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "profile.yaml").write_text("id: p1\ncontrols: [A]\n", encoding="utf-8")

    assert cd._load_profiles(tmp_path) == {"p1": ("A",)}


def test_a_profile_without_an_id_falls_back_to_its_directory_name(tmp_path: Path) -> None:
    (tmp_path / "github-level-1").mkdir()
    (tmp_path / "github-level-1" / "profile.yaml").write_text("controls: [A]\n", encoding="utf-8")
    assert cd._load_profiles(tmp_path) == {"github-level-1": ("A",)}


# --------------------------------------------------------------------------- #
# Membership delta rendering
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("added", "removed", "expected"),
    [
        (("A", "B"), (), "+A, +B"),
        ((), ("C",), "-C"),
        (("A",), ("C",), "+A; -C"),
        ((), (), ""),
    ],
)
def test_a_profile_membership_delta_reads_as_additions_then_removals(
    added: tuple[str, ...], removed: tuple[str, ...], expected: str
) -> None:
    """The separator carries meaning: `,` joins one direction, `;` divides the two."""

    change = cd.ProfileChange(id="p1", added=added, removed=removed)
    assert cd._profile_change_summary(change) == expected


def test_directories_encountered_during_the_walk_are_not_yielded(tmp_path: Path) -> None:
    """Only files are yielded, and a file inside a subdirectory is still reached.

    Directories are excluded by ``os.walk`` itself, which lists them separately from
    ``filenames`` -- so this no longer exercises the ``is_file()`` check, and the test
    below is what does. What it still pins is that descending into a subdirectory finds
    the file inside it, which the walk rewrite could have broken.
    """

    (tmp_path / "pkg").mkdir()
    _source(tmp_path, "pkg/mod.py", "x = 1")
    assert [p.name for p in wh._iter_candidate_paths(tmp_path)] == ["mod.py"]


def test_an_entry_that_is_not_a_regular_file_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``filenames`` is not the same set as "regular files", and reading the difference hurts.

    ``os.walk`` puts every non-directory entry in ``filenames``: a broken symlink, a FIFO, a
    socket, a device node. Opening a FIFO blocks until a writer appears, which would hang the
    scan on a repository that contains one. ``is_file()`` is what keeps those out.

    The condition is forced rather than built from a real FIFO or symlink, because neither is
    portable: ``os.mkfifo`` does not exist on Windows and ``os.symlink`` needs a privilege
    there. Forcing it keeps the branch covered on every platform the suite runs on.
    """

    _source(tmp_path, "regular.py", "x = 1")
    _source(tmp_path, "special.py", "y = 2")
    real_is_file = Path.is_file

    def _is_file(self: Path) -> bool:
        return False if self.name == "special.py" else real_is_file(self)

    monkeypatch.setattr(Path, "is_file", _is_file)
    assert [p.name for p in wh._iter_candidate_paths(tmp_path)] == ["regular.py"]


def test_every_yielded_path_is_under_the_target(tmp_path: Path) -> None:
    """Callers name findings with ``relative_to(repo_root)``; a path outside it would raise.

    The walker used to guard that with a try/except around ``relative_to``, because
    ``rglob`` could be handed anything. ``os.walk`` descends from the root and does not
    follow symlinks, so every path is under the root by construction and the guard became
    unreachable. What the guard protected is still worth asserting -- it is the precondition
    every caller depends on -- so it is asserted directly instead of simulated.
    """

    _source(tmp_path, "app.py", "x = 1")
    _source(tmp_path, "pkg/nested.py", "y = 2")
    outside = tmp_path.parent / f"outside-{tmp_path.name}.py"
    outside.write_text("z = 3", encoding="utf-8")
    try:
        yielded = list(wh._iter_candidate_paths(tmp_path))
        assert yielded, "the fixture produced no candidates, so the assertion below is vacuous"
        for path in yielded:
            path.relative_to(tmp_path)
        assert outside not in yielded
    finally:
        outside.unlink()
