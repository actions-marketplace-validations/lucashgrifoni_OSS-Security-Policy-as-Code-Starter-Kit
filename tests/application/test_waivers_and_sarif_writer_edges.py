"""Waivers, and the SARIF the kit hands to a code-scanning dashboard.

A waiver is the one construct in the kit that turns a failing control green, so everything about
reading one is asymmetric: an unreadable field must never resolve to "waived". The status check
here is the sharp end -- a waiver whose `status` is not a status word at all is dropped *with a
warning*, because silently ignoring it would leave an operator believing a control is waived
while the engine still fails it, and silently honouring it would waive a control nobody approved.

The SARIF side is smaller but has the same shape. Its level mapping is what a dashboard sorts by,
and its path check is what stops a control from pointing an annotation at `/etc/passwd` or at a
path that escapes the repository.
"""

from __future__ import annotations

import os
from datetime import UTC, date, datetime

import pytest

from oss_policy_kit.application import vuln_waivers
from oss_policy_kit.application.sarif_writer import _is_safe_relative_path, _level_for_status
from oss_policy_kit.application.waivers import _parse_date, _waiver_status
from oss_policy_kit.domain.models import ControlStatus

# --------------------------------------------------------------------------- #
# Waiver status
# --------------------------------------------------------------------------- #


def test_a_waiver_with_no_status_keeps_the_documented_default() -> None:
    """Most waivers never write one, and changing that default would revoke them all at once."""

    warnings: list[str] = []
    assert _waiver_status("CI-PIN-008", {"reason": "accepted"}, warnings) == "approved"
    assert warnings == []


@pytest.mark.parametrize("status", ["approved", "APPROVED", "  approved  "])
def test_an_approving_status_is_normalised(status: str) -> None:
    warnings: list[str] = []
    assert _waiver_status("CI-PIN-008", {"status": status}, warnings) == "approved"


@pytest.mark.parametrize("status", ["pending", "rejected", "revoked", "draft"])
def test_a_status_that_does_not_authorize_a_waiver_is_dropped_with_a_reason(status: str) -> None:
    """Dropping it quietly would leave the operator expecting a waiver that never applies."""

    warnings: list[str] = []
    assert _waiver_status("CI-PIN-008", {"status": status}, warnings) is None
    assert len(warnings) == 1
    assert status in warnings[0]


@pytest.mark.parametrize("value", [True, 7, None, ["approved"], {"state": "approved"}])
def test_a_status_that_is_not_a_word_at_all_is_dropped_with_a_reason(value: object) -> None:
    """`True` is the one to watch: a bare `status: yes` in YAML arrives here as a boolean."""

    warnings: list[str] = []
    assert _waiver_status("CI-PIN-008", {"status": value}, warnings) is None
    assert len(warnings) == 1
    assert "not a status word" in warnings[0]


# --------------------------------------------------------------------------- #
# Expiry dates
# --------------------------------------------------------------------------- #


def test_a_date_is_taken_as_written() -> None:
    assert _parse_date(date(2026, 8, 12)) == date(2026, 8, 12)


def test_a_timestamp_is_reduced_to_its_date() -> None:
    """YAML parses `2026-08-12T23:59:59Z` as a datetime; a waiver expires on a day, not a second."""

    assert _parse_date(datetime(2026, 8, 12, 23, 59, 59, tzinfo=UTC)) == date(2026, 8, 12)


def test_a_written_date_is_parsed() -> None:
    assert _parse_date("2026-08-12") == date(2026, 8, 12)


def test_no_expiry_at_all_is_the_only_thing_that_reads_as_no_expiry() -> None:
    assert _parse_date(None) is None


@pytest.mark.parametrize("value", ["", "   ", "next Tuesday", "2026-13-45", "soon"])
def test_an_expiry_that_cannot_be_read_is_refused_rather_than_dropped(value: str) -> None:
    """Dropping it would turn a typo into a waiver that never expires -- the worst outcome here.

    A waiver with no expiry is permanent by design, so "unreadable" must not collapse into
    "absent". The loader raises and the operator fixes one line.
    """

    with pytest.raises(ValueError, match="ISO-8601 date"):
        _parse_date(value)


def test_trailing_text_after_a_date_is_named_specifically() -> None:
    """`2026-08-12 (renew then)` looks parseable; the message says the remainder is not dropped."""

    with pytest.raises(ValueError, match="trailing text"):
        _parse_date("2026-08-12 (renew then)")


@pytest.mark.parametrize("key", ["expiry", "Expires-At", "expires_on", "EXPIRATION"])
def test_an_expiry_shaped_key_is_recognised_so_it_can_be_reported(key: str) -> None:
    """A waiver whose expiry is under a key the loader does not read never expires at all."""

    assert vuln_waivers._looks_like_expiry_key(key) is True


@pytest.mark.parametrize("key", ["reason", "owner", "expert", 7, None, ("expires",)])
def test_a_key_that_is_not_expiry_shaped_is_left_alone(key: object) -> None:
    """`expert` starts with "exp" but not "expir"; the prefix is deliberately that specific."""

    assert vuln_waivers._looks_like_expiry_key(key) is False


# --------------------------------------------------------------------------- #
# The pinned clock
# --------------------------------------------------------------------------- #


def test_without_source_date_epoch_the_pinned_clock_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """`None` means "the pin cannot have altered an expiry decision", and unset is that case."""

    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    assert vuln_waivers._pinned_today() is None


_PINNED_EPOCH = "1781524800"  # 2026-06-15T12:00Z, the epoch conftest pins the suite to
_PINNED_DAY = date(2026, 6, 15)


class _FixedClock:
    """Stands in for `datetime` so the comparison never reads the real wall clock.

    `_pinned_today` is the one place that deliberately compares the pinned clock against the
    unpinned one, which makes it the one test that cannot simply use `utc_now()`. Reading the
    real clock here would make the outcome depend on the day the suite runs -- the exact
    calendar drift the pin exists to eliminate.
    """

    day = _PINNED_DAY

    @classmethod
    def now(cls, _tz: object = None) -> datetime:
        return datetime(cls.day.year, cls.day.month, cls.day.day, 12, 0, tzinfo=UTC)


def test_a_pin_that_resolves_to_today_also_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reporting a pin that matches the wall clock would be a warning about nothing."""

    monkeypatch.setitem(os.environ, "SOURCE_DATE_EPOCH", _PINNED_EPOCH)
    monkeypatch.setattr(vuln_waivers, "datetime", _FixedClock)

    assert vuln_waivers._pinned_today() is None


def test_a_pin_to_another_day_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    """This is the case an operator has to know about: expiry was judged against a fixed date."""

    class _Tomorrow(_FixedClock):
        day = date(2026, 6, 16)

    monkeypatch.setitem(os.environ, "SOURCE_DATE_EPOCH", _PINNED_EPOCH)
    monkeypatch.setattr(vuln_waivers, "datetime", _Tomorrow)

    assert vuln_waivers._pinned_today() == _PINNED_DAY


# --------------------------------------------------------------------------- #
# SARIF levels and paths
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "level"),
    [
        (ControlStatus.FAIL, "error"),
        (ControlStatus.MANUAL_REVIEW_REQUIRED, "warning"),
        (ControlStatus.PASS, "note"),
        (ControlStatus.NOT_APPLICABLE, "note"),
        (ControlStatus.WAIVED, "note"),
    ],
)
def test_each_status_maps_to_the_level_a_dashboard_sorts_by(status: ControlStatus, level: str) -> None:
    """`manual-review-required` is a warning, not an error: nobody has said the control failed."""

    assert _level_for_status(status) == level


@pytest.mark.parametrize(
    "value",
    [".github/workflows/ci.yml", "src/app.py", "a/b/c.txt"],
)
def test_a_path_inside_the_repository_is_accepted(value: str) -> None:
    assert _is_safe_relative_path(value) is True


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("empty", ""),
        ("absolute posix", "/etc/passwd"),
        ("a windows drive", "C:/Windows/System32"),
        ("a url", "https://example.com/x"),
        ("an escape", "../../etc/passwd"),
        ("an escape mid-path", "src/../../secrets"),
        ("a backslash escape", "..\\..\\secrets"),
    ],
)
def test_a_path_that_leaves_the_repository_is_refused(label: str, value: str) -> None:
    """The annotation is rendered by a dashboard against the repo; it must stay inside it."""

    assert _is_safe_relative_path(value) is False, label


def test_a_directory_named_with_dots_is_not_an_escape() -> None:
    """`..` is only an escape as a whole segment; `..foo` is somebody's directory."""

    assert _is_safe_relative_path("src/..foo/bar.py") is True
