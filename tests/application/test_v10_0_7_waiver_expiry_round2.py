"""v10.0.7 round 2: two remaining ways a waiver outlives its own expiry date.

Both are fail-open — the waiver keeps suppressing its finding, and ``emit-vex``
keeps publishing ``"state": "not_affected"`` off it:

* **trailing junk after an ISO date prefix.** Both loaders parsed ``text[:10]``,
  so ``"2099-01-01-NOT-A-DATE"`` and ``"2099-01-01 please ignore"`` became
  2099-01-01 with no warning at all. Whatever the operator wrote after the date —
  a note, a second date, a typo'd separator — was dropped without a word. The
  value must now parse whole, and a date followed by anything else is rejected
  with the date it found named.

* **``SOURCE_DATE_EPOCH`` pinned before the expiry.** ``domain.models.utc_now``
  honours the variable deliberately (that is what makes artifacts reproducible and
  this suite calendar-immune), and the expiry comparison reads that clock, so a
  waiver that lapsed in 2020 applies again: exit 0 instead of 1, gate disarmed,
  nothing on screen. The expiry decision stays on the pinned clock — moving it to
  the wall clock would resurrect the date-rot class v9.0.3 killed — but it may
  never be silent: when the pinned date is the only reason a waiver still applies,
  a warning naming ``SOURCE_DATE_EPOCH`` rides along with it.

The pinned-clock warning fires only when the pinned date genuinely decided the
outcome (live against the pinned date, dead against the real one), so a waiver
that is live on both clocks stays warning-free.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from oss_policy_kit.application import vuln_waivers
from oss_policy_kit.application.vuln_waivers import (
    expiry_date_from_text,
    load_vuln_waivers,
    parse_waiver_expiry,
    pinned_expiry_clock_note,
)
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli.emit_vex import _run_emit_vex

_CVE = "CVE-2026-777"
#: tests/conftest.py pins SOURCE_DATE_EPOCH to 2026-06-15T12:00Z.
_PINNED_TODAY = date(2026, 6, 15)

#: 2020-01-01T00:00:00Z — before ``_LAPSED``, and long before the real date.
_EPOCH_2020 = "1577836800"
_LAPSED = "2020-06-01"

#: A date prefix that parses, followed by text the loader used to throw away.
_JUNK_EXPIRIES = [
    "2099-01-01-NOT-A-DATE",
    "2099-01-01 please ignore",
    "2099-01-01 renewed to 2030-01-01",
    "2099-01-01/2030-01-01",
    "2099-01-01x",
]


def _vuln_waivers(tmp_path: Path, *fields: str, name: str = "waivers.yaml") -> Path:
    lines = [
        "waivers:",
        f"  - vulnerability_ids: [{_CVE}]",
        "    owner: appsec",
        "    justification: reviewed, not reachable",
        *(f"    {field}" for field in fields),
    ]
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _control_waivers(tmp_path: Path, *fields: str, name: str = "waivers.yaml") -> Path:
    lines = [
        "waivers:",
        "  - control_id: GOV-SEC-001",
        "    owner: appsec",
        "    justification: reviewed, compensating control in place",
        *(f"    {field}" for field in fields),
    ]
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _osv_sarif(tmp_path: Path) -> Path:
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "osv-scanner", "version": "2.0.0", "rules": [{"id": _CVE}]}},
                "results": [{"ruleId": _CVE, "level": "error", "message": {"text": "vulnerable dep"}}],
            }
        ],
    }
    path = tmp_path / "osv-scanner.sarif.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# an ISO date prefix followed by junk is not a date
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", _JUNK_EXPIRIES)
def test_vuln_waiver_expiry_with_trailing_junk_is_not_silently_truncated(value: str, tmp_path: Path) -> None:
    """The headline: junk after the date must not be dropped without a word."""

    mapping, warnings = load_vuln_waivers(_vuln_waivers(tmp_path, f'expires_at: "{value}"'))
    assert mapping == {}
    assert any("trailing text after 2099-01-01" in w for w in warnings), warnings


@pytest.mark.parametrize("value", _JUNK_EXPIRIES)
def test_control_waiver_expiry_with_trailing_junk_is_not_silently_truncated(value: str, tmp_path: Path) -> None:
    """Same value on the control-gate loader: dropped loudly, never truncated."""

    outcome = parse_waivers_file(_control_waivers(tmp_path, f'expires_at: "{value}"'))
    assert "GOV-SEC-001" not in outcome.by_control
    assert any("invalid expires_at" in w and "trailing text after 2099-01-01" in w for w in outcome.warnings), (
        outcome.warnings
    )


def test_legacy_expires_on_spelling_gets_the_same_discipline(tmp_path: Path) -> None:
    """The alias the kit's own docs teach must not be the loose one."""

    mapping, warnings = load_vuln_waivers(_vuln_waivers(tmp_path, 'expires_on: "2099-01-01-NOT-A-DATE"'))
    assert mapping == {}
    assert any("expires_on" in w and "trailing text" in w for w in warnings), warnings


def test_emit_vex_does_not_publish_not_affected_from_a_junk_suffixed_expiry(tmp_path: Path) -> None:
    """End-to-end: the truncated date must not become a not_affected claim."""

    out = tmp_path / "vex.json"
    _run_emit_vex(
        _osv_sarif(tmp_path),
        out,
        _vuln_waivers(tmp_path, 'expires_at: "2099-01-01 please ignore"'),
        validate_output=True,
        include_references=False,
    )
    doc = json.loads(out.read_text(encoding="utf-8"))
    states = {v["id"]: v["analysis"]["state"] for v in doc["vulnerabilities"]}
    assert states[_CVE] == "in_triage"


def test_unparseable_value_without_a_date_prefix_keeps_its_own_wording(tmp_path: Path) -> None:
    """A value with no date at all is 'unparseable', not 'trailing text'."""

    mapping, warnings = load_vuln_waivers(_vuln_waivers(tmp_path, 'expires_at: "soon"'))
    assert mapping == {}
    assert any("unparseable" in w for w in warnings), warnings
    assert not any("trailing text" in w for w in warnings), warnings


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2099-12-31", date(2099, 12, 31)),
        ("20991231", date(2099, 12, 31)),
        ("2099-12-31T00:00:00Z", date(2099, 12, 31)),
        ("2099-12-31T12:34:56+00:00", date(2099, 12, 31)),
        ("2099-12-31 12:34:56", date(2099, 12, 31)),
    ],
)
def test_whole_iso_values_still_parse(value: str, expected: date, tmp_path: Path) -> None:
    """Regression fence: every spelling the kit documents keeps working, warning-free."""

    assert expiry_date_from_text(value) == expected
    mapping, warnings = load_vuln_waivers(_vuln_waivers(tmp_path, f'expires_at: "{value}"'))
    assert mapping[_CVE].expires_at == expected
    assert warnings == []

    outcome = parse_waivers_file(_control_waivers(tmp_path, f'expires_at: "{value}"', name="control.yaml"))
    assert outcome.by_control["GOV-SEC-001"].expires_at == expected
    assert outcome.warnings == []


def test_expiry_date_from_text_rejects_a_truncatable_prefix() -> None:
    """The shared parser itself refuses to consume only the first ten characters."""

    assert expiry_date_from_text("2099-01-01-NOT-A-DATE") is None
    assert expiry_date_from_text("2099-01-01 please ignore") is None
    assert expiry_date_from_text("2099-01-01") == date(2099, 1, 1)


# --------------------------------------------------------------------------- #
# SOURCE_DATE_EPOCH may pin the comparison, but never silently
# --------------------------------------------------------------------------- #


def test_pinned_clock_resurrecting_a_lapsed_vuln_waiver_is_never_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pinned before the expiry, the waiver applies again — and says so."""

    monkeypatch.setenv("SOURCE_DATE_EPOCH", _EPOCH_2020)
    mapping, warnings = load_vuln_waivers(_vuln_waivers(tmp_path, f'expires_at: "{_LAPSED}"'))
    assert _CVE in mapping  # contract: the pinned clock still decides the outcome
    assert any("SOURCE_DATE_EPOCH" in w and _LAPSED in w for w in warnings), warnings


def test_pinned_clock_resurrecting_a_lapsed_control_waiver_is_never_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same disarmed gate on the control surface, same visible reason."""

    monkeypatch.setenv("SOURCE_DATE_EPOCH", _EPOCH_2020)
    outcome = parse_waivers_file(_control_waivers(tmp_path, f'expires_at: "{_LAPSED}"'))
    assert "GOV-SEC-001" in outcome.by_control
    assert any("SOURCE_DATE_EPOCH" in w and _LAPSED in w for w in outcome.warnings), outcome.warnings


def test_without_the_pinned_clock_the_same_waiver_is_simply_expired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proof the warning describes a real disarm: unpinned, the waiver is dead."""

    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    mapping, warnings = load_vuln_waivers(_vuln_waivers(tmp_path, f'expires_at: "{_LAPSED}"'))
    assert mapping == {}
    assert any("expired at" in w for w in warnings), warnings

    outcome = parse_waivers_file(_control_waivers(tmp_path, f'expires_at: "{_LAPSED}"', name="control.yaml"))
    assert "GOV-SEC-001" not in outcome.by_control
    assert any("expired at" in w for w in outcome.warnings), outcome.warnings


def test_a_waiver_live_on_both_clocks_gets_no_pinned_clock_noise(tmp_path: Path) -> None:
    """The suite's own pinned clock must not annotate every ordinary waiver."""

    mapping, warnings = load_vuln_waivers(_vuln_waivers(tmp_path, 'expires_at: "2099-12-31"'))
    assert mapping[_CVE].expires_at == date(2099, 12, 31)
    assert warnings == []

    outcome = parse_waivers_file(_control_waivers(tmp_path, 'expires_at: "2099-12-31"', name="control.yaml"))
    assert outcome.by_control["GOV-SEC-001"].expires_at is not None
    assert outcome.warnings == []


def test_pinned_note_is_withheld_when_the_caller_supplied_its_own_today() -> None:
    """A caller-chosen ``today`` was not the pinned clock, so it must not be blamed on it."""

    assert pinned_expiry_clock_note(date(2020, 6, 1), date(2020, 1, 1)) is None
    assert pinned_expiry_clock_note(None, _PINNED_TODAY) is None
    assert pinned_expiry_clock_note(date(2099, 12, 31), _PINNED_TODAY) is None


def test_pinning_to_the_current_date_is_not_reported_as_a_pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """SOURCE_DATE_EPOCH set to today changes no expiry outcome, so it earns no note.

    ``utc_now()``, not ``datetime.now()``: the suite pins ``SOURCE_DATE_EPOCH`` in
    conftest precisely so no test drifts against the calendar, and
    ``tests/test_suite_clock_hygiene.py`` enforces it. Reading the real clock in a test
    ABOUT the pinned clock is the date-rot class this repository already closed once.
    """

    pinned_day = date(2026, 6, 15)
    midnight = datetime(pinned_day.year, pinned_day.month, pinned_day.day, tzinfo=UTC)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(int(midnight.timestamp())))
    # The real clock is pinned through the module's own seam rather than read: the note
    # exists to say "live on the pinned clock, dead on the real one", so the case where
    # they AGREE cannot be expressed without controlling both.
    monkeypatch.setattr(vuln_waivers, "_real_today", lambda: pinned_day)

    # Live against the pinned date and against the real one: nothing was disarmed.
    assert pinned_expiry_clock_note(date(2099, 1, 1), pinned_day) is None, (
        "pinning to the date it already is disarms nothing, so it earns no note"
    )
    # Dead against BOTH: the waiver is simply expired, and the pin kept nothing alive.
    assert pinned_expiry_clock_note(date(2020, 6, 1), pinned_day) is None, (
        "an already-expired waiver must not be blamed on SOURCE_DATE_EPOCH"
    )

    # The one case the note exists for: live on the pinned clock, dead on the real one.
    monkeypatch.setattr(vuln_waivers, "_real_today", lambda: date(2099, 6, 1))
    note = pinned_expiry_clock_note(date(2026, 12, 31), pinned_day)
    assert note is not None
    assert "SOURCE_DATE_EPOCH" in note


def test_pinned_note_reaches_the_helper_emit_vex_re_exports(monkeypatch: pytest.MonkeyPatch) -> None:
    """``parse_waiver_expiry`` carries the note, so emit-vex/correlate-findings both see it."""

    monkeypatch.setenv("SOURCE_DATE_EPOCH", _EPOCH_2020)
    warnings: list[str] = []
    assert parse_waiver_expiry(0, {"expires_at": _LAPSED}, date(2020, 1, 1), warnings) == (date(2020, 6, 1), True)
    assert any("SOURCE_DATE_EPOCH" in w for w in warnings), warnings
