"""What a user-supplied enrichment snapshot may and may not change.

The snapshot is a file the adopter brings -- an offline EPSS/KEV export, however they obtained
it -- so the kit accepts it for *ranking only* (ADR-030 Amendment / D6). It reorders the list; it
never edits a finding's own `kev` or `epss` field, never changes a severity, and never touches a
control state. Anything else would let an unverifiable file rewrite the report's claims.

Two rules make that safe, and both are asserted here. A value the scanner reported always wins,
because the scanner is the accountable source. And a value the snapshot cannot supply cleanly --
missing, the wrong type, or a probability outside [0, 1] -- is ignored rather than coerced, so a
garbage number cannot warp the order.
"""

from __future__ import annotations

from typing import Any

import pytest

from oss_policy_kit.application.finding_correlation import _effective_signals
from oss_policy_kit.domain.findings import (
    FindingLocation,
    FindingSource,
    NormalizedFinding,
    SeverityView,
)


def _finding(*, vuln_id: str = "CVE-2026-1", epss: float | None = None, kev: bool | None = None) -> NormalizedFinding:
    return NormalizedFinding(
        id="",
        sources=(
            FindingSource(
                tool="osv-scanner",
                source_path=".oss-policy-kit/evidence/osv-scanner.json",
                rule=vuln_id,
                severity_original="high",
                message="msg",
            ),
        ),
        rule=vuln_id,
        message="msg",
        severity=SeverityView(normalized="high", by_source=(("osv-scanner", "high"),)),
        location=FindingLocation(),
        vulnerability_ids=(vuln_id,),
        epss=epss,
        kev=kev,
    )


# --------------------------------------------------------------------------- #
# Nothing to enrich with
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("enrichment", [None, {}])
def test_without_a_snapshot_the_finding_speaks_for_itself(enrichment: dict[str, Any] | None) -> None:
    kev, epss, contributed = _effective_signals(_finding(kev=True, epss=0.7), enrichment)

    assert (kev, epss) == (True, 0.7)
    assert contributed is False


def test_a_snapshot_with_no_entry_for_this_vulnerability_contributes_nothing() -> None:
    kev, epss, contributed = _effective_signals(_finding(), {"CVE-2026-9": {"kev": True, "epss": 0.9}})

    assert (kev, epss, contributed) == (False, None, False)


@pytest.mark.parametrize("entry", ["high", 42, None, ["kev"]])
def test_an_entry_that_is_not_an_object_is_walked_past(entry: Any) -> None:
    _kev, _epss, contributed = _effective_signals(_finding(), {"CVE-2026-1": entry})

    assert contributed is False


# --------------------------------------------------------------------------- #
# The scanner wins
# --------------------------------------------------------------------------- #


def test_a_scanner_reported_kev_is_not_overwritten_by_the_snapshot() -> None:
    """`kev=False` from the scanner is an answer, not a gap; the snapshot must not flip it."""

    kev, _epss, contributed = _effective_signals(_finding(kev=False), {"CVE-2026-1": {"kev": True}})

    assert kev is False
    assert contributed is False


def test_a_scanner_reported_epss_is_not_overwritten_by_the_snapshot() -> None:
    _kev, epss, contributed = _effective_signals(_finding(epss=0.1), {"CVE-2026-1": {"epss": 0.9}})

    assert epss == 0.1
    assert contributed is False


# --------------------------------------------------------------------------- #
# Filling a genuine gap
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw_kev", [True, 1, "true", "TRUE", "  yes  ", "1"])
def test_a_snapshot_can_fill_a_missing_kev_flag(raw_kev: Any) -> None:
    """Exports spell this several ways; each is accepted and each is recorded as contributed."""

    kev, _epss, contributed = _effective_signals(_finding(), {"CVE-2026-1": {"kev": raw_kev}})

    assert kev is True
    assert contributed is True


@pytest.mark.parametrize("raw_kev", [False, 0, "false", "no", "", "maybe", None, {"listed": True}])
def test_a_kev_value_that_does_not_say_yes_is_not_read_as_yes(raw_kev: Any) -> None:
    """KEV means "actively exploited"; inferring it from an ambiguous value would be a claim."""

    kev, _epss, contributed = _effective_signals(_finding(), {"CVE-2026-1": {"kev": raw_kev}})

    assert kev is False
    assert contributed is False


@pytest.mark.parametrize(("raw_epss", "expected"), [(0.42, 0.42), ("0.42", 0.42), (0, 0.0), (1, 1.0)])
def test_a_snapshot_can_fill_a_missing_epss_score(raw_epss: Any, expected: float) -> None:
    _kev, epss, contributed = _effective_signals(_finding(), {"CVE-2026-1": {"epss": raw_epss}})

    assert epss == expected
    assert contributed is True


@pytest.mark.parametrize(
    ("label", "raw_epss"),
    [
        ("absent", None),
        ("prose", "high"),
        ("a list", [0.4]),
        ("a mapping", {"score": 0.4}),
        ("above one", 999),
        ("below zero", -1),
    ],
)
def test_an_epss_value_that_is_not_a_probability_is_ignored(label: str, raw_epss: Any) -> None:
    """A garbage number would not merely be wrong -- it would reorder the whole list."""

    _kev, epss, contributed = _effective_signals(_finding(), {"CVE-2026-1": {"epss": raw_epss}})

    assert epss is None, label
    assert contributed is False


def test_one_snapshot_entry_can_fill_both_gaps_at_once() -> None:
    kev, epss, contributed = _effective_signals(_finding(), {"CVE-2026-1": {"kev": "true", "epss": "0.63"}})

    assert (kev, epss, contributed) == (True, 0.63, True)
