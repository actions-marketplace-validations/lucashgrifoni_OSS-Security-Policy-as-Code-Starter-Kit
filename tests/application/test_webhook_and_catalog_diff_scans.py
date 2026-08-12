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

    def _boom(_self: Path, _pattern: str) -> object:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "rglob", _boom)
    assert list(wh._iter_candidate_paths(tmp_path)) == []


def test_a_file_that_cannot_be_read_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """One unreadable file must not hide the signals in the readable ones beside it."""

    _source(tmp_path, "locked.py", "x-hub-signature-256")
    _source(tmp_path, "routes.py", "@app.post('/webhook')")

    real_read_bytes = Path.read_bytes

    def _read_bytes(self: Path) -> bytes:
        if self.name == "locked.py":
            raise OSError(13, "Permission denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    has_route, route_hint, _sig, _sh, _replay, _rh = wh._scan_signals(tmp_path)
    assert has_route is True
    assert route_hint == "routes.py"


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
    """The unreadable file is named so it is walked first; otherwise the match short-circuits."""

    _source(tmp_path, "a_locked.py", "cosign")
    _source(tmp_path, "z_good.py", "cosign verify-blob")

    real_read_bytes = Path.read_bytes

    def _read_bytes(self: Path) -> bytes:
        if self.name == "a_locked.py":
            raise OSError(13, "Permission denied")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _read_bytes)
    assert wh._scan_for_any(tmp_path, ("cosign",)) == "z_good.py"


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
    """`rglob("*")` yields directories too; only files can be read for signals."""

    (tmp_path / "pkg").mkdir()
    _source(tmp_path, "pkg/mod.py", "x = 1")
    assert [p.name for p in wh._iter_candidate_paths(tmp_path)] == ["mod.py"]


def test_a_path_that_is_not_under_the_target_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A symlinked entry can resolve outside the root; it has no repo-relative name to report."""

    _source(tmp_path, "app.py", "x = 1")
    real_relative_to = Path.relative_to

    def _relative_to(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name == "app.py":
            raise ValueError("not under the target")
        return real_relative_to(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "relative_to", _relative_to)
    assert list(wh._iter_candidate_paths(tmp_path)) == []
