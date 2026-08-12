"""How old a Scorecard result is allowed to be before the kit stops trusting it.

A Scorecard export is a snapshot of a repository at a moment. Reporting a year-old snapshot as
current posture is the failure this guards against, and it is a quiet one -- the numbers look
right, they are simply about a repository that no longer exists in that form.

Three decisions live here and each has a reason to be exactly what it is: a date the kit cannot
read is `undated` rather than `stale`, because "we do not know when this was taken" and "this is
old" are different things to tell an auditor; a naive timestamp is assumed UTC rather than
refused, since Scorecard has emitted both and refusing would fail honest exports; and a
future-dated result is `fresh`, because clock skew on a runner should not age a result that was
produced seconds ago.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from oss_policy_kit.application.scorecard_ingest import _freshness

_NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
_MAX_AGE = 90


def _freshness_of(result_date: str | None, *, now: datetime = _NOW) -> str:
    return _freshness(result_date, now=now, max_age_days=_MAX_AGE)


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("nothing at all", None),
        ("an empty string", ""),
        ("prose instead of a date", "last Tuesday"),
        ("a date that does not exist", "2026-02-30"),
        ("a partial timestamp", "2026-08"),
    ],
)
def test_a_date_the_kit_cannot_read_is_undated_not_stale(label: str, value: str | None) -> None:
    """ "We do not know when this was taken" is a different thing to report than "this is old"."""

    assert _freshness_of(value) == "undated", label


def test_a_recent_result_is_fresh() -> None:
    assert _freshness_of("2026-08-01T00:00:00Z") == "fresh"


def test_a_result_older_than_the_ceiling_is_stale() -> None:
    old = (_NOW - timedelta(days=_MAX_AGE + 1)).isoformat()
    assert _freshness_of(old) == "stale"


def test_a_result_exactly_at_the_ceiling_is_still_fresh() -> None:
    """The boundary is inclusive; an off-by-one here silently ages a whole day of results."""

    edge = (_NOW - timedelta(days=_MAX_AGE)).isoformat()
    assert _freshness_of(edge) == "fresh"


def test_a_timestamp_without_a_zone_is_read_as_utc() -> None:
    """Scorecard has emitted both; refusing the naive form would fail honest exports."""

    assert _freshness_of("2026-08-01T00:00:00") == "fresh"


def test_a_naive_now_is_also_read_as_utc() -> None:
    """The caller's clock is not the kit's to validate, but it must not crash the comparison."""

    naive_now = datetime(2026, 8, 12, 12, 0)  # noqa: DTZ001 - the point of the test
    assert _freshness(("2026-08-01T00:00:00Z"), now=naive_now, max_age_days=_MAX_AGE) == "fresh"


def test_a_future_dated_result_is_fresh_rather_than_impossibly_old() -> None:
    """Runner clock skew must not age a result that was produced seconds ago."""

    future = (_NOW + timedelta(days=3)).isoformat()
    assert _freshness_of(future) == "fresh"
