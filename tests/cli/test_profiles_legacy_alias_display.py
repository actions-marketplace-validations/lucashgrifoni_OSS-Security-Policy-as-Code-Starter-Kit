"""The legacy-alias rows in `profiles`, which no bundled alias currently produces.

`BUNDLED_PROFILE_LEGACY_IDS` derives from `PROFILE_DIRECTORY_ALIASES`, and that map has been
empty since v10.0.0 removed the CRA alias. So the whole legacy-display path -- suppressing
the canonical directory row, adding the deprecated id back as its own row, and widening the
column to fit the `(legacy -> ...)` suffix -- cannot run on any real input today.

That makes it dormant, not dead: the mechanism is deliberately data-driven so the next
deprecation gets the display for free. What was missing is any evidence that it still works.
These tests inject an alias between two real bundled profiles and assert the three things
that path is supposed to do, so a refactor cannot quietly break a capability nothing
currently exercises.

The same pattern as the deprecation warning in `cli/common.py`: prove the mechanism, do not
delete it, and do not pretend a real alias exists.
"""

from __future__ import annotations

import pytest

from oss_policy_kit.cli import profiles as pr

_DEPRECATED = "github-level-1"
_CANONICAL = "github-level-2"


@pytest.fixture
def injected_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend `github-level-1` was renamed to `github-level-2`.

    Both are real bundled profiles, so every load the display path performs still succeeds
    and the test exercises the branch rather than a stub.
    """

    monkeypatch.setattr(pr, "_PROFILE_DISPLAY_ALIAS_TARGETS", {_DEPRECATED: _CANONICAL})
    monkeypatch.setattr(pr, "BUNDLED_PROFILE_LEGACY_IDS", frozenset({_DEPRECATED}))
    monkeypatch.setattr(pr, "PROFILE_DIRECTORY_ALIASES", {_DEPRECATED: _CANONICAL})


def _rows_by_id(rows: list[pr._ProfileDisplayRow]) -> dict[str, pr._ProfileDisplayRow]:
    return {r.profile_id: r for r in rows}


# --------------------------------------------------------------------------- #
# today: no aliases at all
# --------------------------------------------------------------------------- #


def test_no_row_is_a_legacy_alias_today() -> None:
    """v10.0.0 emptied the map; a legacy row now would be a false deprecation notice."""

    rows = pr._iter_bundled_profiles()

    assert rows
    assert [r.profile_id for r in rows if r.is_legacy_alias] == []


def test_every_bundled_profile_directory_gets_a_row_today() -> None:
    """The suppression branch below must not be firing on real input."""

    rows = pr._iter_bundled_profiles()
    ids = {r.profile_id for r in rows}

    assert _DEPRECATED in ids
    assert _CANONICAL in ids


# --------------------------------------------------------------------------- #
# with an alias injected: the three things the display path must do
# --------------------------------------------------------------------------- #


def test_the_deprecated_id_is_shown_as_a_legacy_alias(injected_alias: None) -> None:
    """It stays listed so someone still using the old id can find it."""

    rows = _rows_by_id(pr._iter_bundled_profiles())

    assert _DEPRECATED in rows
    assert rows[_DEPRECATED].is_legacy_alias is True


def test_the_canonical_profile_keeps_its_own_ordinary_row(injected_alias: None) -> None:
    rows = _rows_by_id(pr._iter_bundled_profiles())

    assert rows[_CANONICAL].is_legacy_alias is False


def test_the_deprecated_id_appears_exactly_once(injected_alias: None) -> None:
    """The directory row is suppressed so the alias is not listed twice.

    Without the suppression the same profile would appear as both a normal entry and a
    legacy one, which reads as two different profiles with identical contents.
    """

    ids = [r.profile_id for r in pr._iter_bundled_profiles()]

    assert ids.count(_DEPRECATED) == 1


def test_the_legacy_row_carries_the_canonical_profiles_metadata(injected_alias: None) -> None:
    """The row is a pointer at the canonical profile, so its numbers must be that profile's.

    Showing the deprecated id beside stale control counts would be worse than not listing
    it at all.
    """

    rows = _rows_by_id(pr._iter_bundled_profiles())

    assert rows[_DEPRECATED].controls > 0
    assert rows[_DEPRECATED].title.strip()


def test_the_id_column_widens_to_fit_the_legacy_suffix(injected_alias: None) -> None:
    """The rendered id is `<legacy> (legacy -> <canonical>)`; a column sized to the bare id
    would truncate it."""

    rows = pr._iter_bundled_profiles()

    width = pr._longest_profile_id_len(rows)

    assert width >= len(_DEPRECATED) + len(" (legacy -> )") + len(_CANONICAL)


def test_legacy_rows_sort_after_their_platform_peers(injected_alias: None) -> None:
    """Deprecated entries belong at the end of their platform group, not interleaved."""

    rows = [r for r in pr._iter_bundled_profiles() if r.platform == "GitHub"]

    assert rows
    assert rows[-1].is_legacy_alias is True


def test_a_legacy_id_that_still_has_its_own_directory_row_is_not_added_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two maps can disagree, and the listing has to survive it.

    `BUNDLED_PROFILE_LEGACY_IDS` says which ids are deprecated; `_PROFILE_DISPLAY_ALIAS_TARGETS`
    says which canonical profile each points at, and it is the second one that suppresses the
    directory row. Deprecate an id in the first without adding it to the second -- one line of a
    two-line change -- and the id would be listed once as an ordinary profile and again as a
    legacy alias, reading as two profiles with identical contents.
    """

    monkeypatch.setattr(pr, "BUNDLED_PROFILE_LEGACY_IDS", frozenset({_DEPRECATED}))
    monkeypatch.setattr(pr, "_PROFILE_DISPLAY_ALIAS_TARGETS", {})

    ids = [r.profile_id for r in pr._iter_bundled_profiles()]

    assert ids.count(_DEPRECATED) == 1
    assert all(r.is_legacy_alias is False for r in pr._iter_bundled_profiles())
