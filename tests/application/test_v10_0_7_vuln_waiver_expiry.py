"""v10.0.7: a vulnerability-keyed waiver must actually expire.

The loader read only ``expires_at`` while the kit's own remediation text and docs
(``evaluators_iac_cfn`` / ``_pulumi`` / ``_bicep``, ``docs/iac-terraform.md``: "Waivers
must have an ``expires_on``") teach the ``expires_on`` spelling — the same alias the
control-gate loader has accepted since v9.0.2. Every ``expires_on`` on this surface was
therefore read as "no expiry": an entry that expired six years ago still suppressed the
finding, still exempted it from the findings-surface ``--fail-on-*`` gates, and still
published ``"state": "not_affected"`` in the VEX document — with no warning at all.

Fenced here: the legacy alias is honoured; a malformed value on either spelling drops the
entry loudly; two expiry keys that disagree are ambiguous rather than permanent; and an
expiry-shaped key the loader does not read (``expiry``, ``valid_until``, ``Expires-At``)
is never a licence to never expire. Silently defaulting an unknown key to "no expiry" is
how this fail-open class keeps coming back.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from oss_policy_kit.application.vuln_waivers import load_vuln_waivers, parse_waiver_expiry
from oss_policy_kit.cli.emit_vex import _run_emit_vex

_CVE = "CVE-2026-777"
#: tests/conftest.py pins SOURCE_DATE_EPOCH to 2026-06-15T12:00Z, so "today" is fixed.
_TODAY = date(2026, 6, 15)
_PAST = "2020-01-01"
_FUTURE = "2099-12-31"


def _waivers(tmp_path: Path, *fields: str, name: str = "waivers.yaml") -> Path:
    """Write a vulnerability-keyed waiver carrying the extra *fields* verbatim."""

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


def _osv_sarif(tmp_path: Path) -> Path:
    """Minimal OSV-Scanner SARIF carrying the one vulnerability the waiver targets."""

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
# the legacy ``expires_on`` alias is read, and its expiry is honoured
# --------------------------------------------------------------------------- #


def test_expired_legacy_expires_on_no_longer_waives(tmp_path: Path) -> None:
    """The headline fail-open: a waiver that lapsed six years ago must not suppress."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, f'expires_on: "{_PAST}"'))
    assert mapping == {}
    assert any("expired at 2020-01-01" in w for w in warnings), warnings


def test_future_legacy_expires_on_still_waives_and_keeps_the_date(tmp_path: Path) -> None:
    """A live ``expires_on`` waives, and the date reaches the record (not None)."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, f'expires_on: "{_FUTURE}"'))
    assert _CVE in mapping
    assert mapping[_CVE].expires_at == date(2099, 12, 31)
    assert warnings == []


@pytest.mark.parametrize("value", ['"not-a-date"', '""', "12345", "yes", "no", "1.5", "[2099-12-31]"])
def test_malformed_legacy_expires_on_fails_closed(value: str, tmp_path: Path) -> None:
    """A blank, typo'd, numeric or boolean ``expires_on`` is never "no expiry"."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, f"expires_on: {value}"))
    assert mapping == {}
    assert any("expires_on" in w for w in warnings), warnings


def test_emit_vex_does_not_publish_not_affected_from_an_expired_legacy_waiver(tmp_path: Path) -> None:
    """End-to-end: the VEX document must not carry a not_affected claim off a lapsed waiver."""

    out = tmp_path / "vex.json"
    _run_emit_vex(
        _osv_sarif(tmp_path),
        out,
        _waivers(tmp_path, f'expires_on: "{_PAST}"'),
        validate_output=True,
        include_references=False,
    )
    doc = json.loads(out.read_text(encoding="utf-8"))
    states = {v["id"]: v["analysis"]["state"] for v in doc["vulnerabilities"]}
    assert states[_CVE] == "in_triage"


# --------------------------------------------------------------------------- #
# an unrecognised or ambiguous expiry key fails closed too
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "key", ["expiry", "expiration_date", "expire_at", "Expires-At", "expires_on_date", "valid_until"]
)
def test_unrecognised_expiry_key_fails_closed(key: str, tmp_path: Path) -> None:
    """An expiry-shaped key the loader does not read must not default to "never expires"."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, f'{key}: "{_PAST}"'))
    assert mapping == {}
    assert any(key in w and "expires_at" in w for w in warnings), warnings


def test_conflicting_expiry_keys_are_ambiguous_not_permanent(tmp_path: Path) -> None:
    """A half-migrated entry cannot hide an expired date behind a live one."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, f'expires_at: "{_FUTURE}"', f'expires_on: "{_PAST}"'))
    assert mapping == {}
    assert any("disagree" in w for w in warnings), warnings


def test_explicit_null_canonical_does_not_mask_an_expired_legacy_alias(tmp_path: Path) -> None:
    """``expires_at:`` (null) plus a lapsed ``expires_on`` keeps the only real date present."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, "expires_at:", f'expires_on: "{_PAST}"'))
    assert mapping == {}
    assert any("expired at 2020-01-01" in w for w in warnings), warnings


def test_agreeing_expiry_keys_are_accepted(tmp_path: Path) -> None:
    """Both spellings on one entry with the same date is redundant, not an error."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, f'expires_at: "{_FUTURE}"', f'expires_on: "{_FUTURE}"'))
    assert _CVE in mapping
    assert mapping[_CVE].expires_at == date(2099, 12, 31)
    assert warnings == []


# --------------------------------------------------------------------------- #
# regression fences: the canonical path and ordinary fields are untouched
# --------------------------------------------------------------------------- #


def test_canonical_expires_at_behaviour_is_unchanged(tmp_path: Path) -> None:
    """The pre-existing ``expires_at`` contract keeps working in both directions."""

    live, live_warnings = load_vuln_waivers(_waivers(tmp_path, f'expires_at: "{_FUTURE}"', name="live.yaml"))
    assert _CVE in live
    assert live[_CVE].expires_at == date(2099, 12, 31)
    assert live_warnings == []

    lapsed, lapsed_warnings = load_vuln_waivers(_waivers(tmp_path, f'expires_at: "{_PAST}"', name="lapsed.yaml"))
    assert lapsed == {}
    assert any("expired at 2020-01-01" in w for w in lapsed_warnings), lapsed_warnings


def test_ordinary_waiver_fields_are_not_mistaken_for_expiry_keys(tmp_path: Path) -> None:
    """The lookalike scan must not flag status / vex_justification / owner and drop a valid waiver."""

    mapping, warnings = load_vuln_waivers(
        _waivers(tmp_path, "status: approved", "vex_justification: code_not_reachable")
    )
    assert _CVE in mapping
    assert mapping[_CVE].expires_at is None
    assert warnings == []


def test_parse_waiver_expiry_reads_the_alias_directly(tmp_path: Path) -> None:
    """The helper emit-vex re-exports as ``_parse_waiver_expiry`` honours the alias itself."""

    warnings: list[str] = []
    assert parse_waiver_expiry(0, {"expires_on": _FUTURE}, _TODAY, warnings) == (date(2099, 12, 31), True)
    assert parse_waiver_expiry(1, {}, _TODAY, warnings) == (None, True)
    assert parse_waiver_expiry(2, {"expires_at": None, "expires_on": None}, _TODAY, warnings) == (None, True)
    assert warnings == []

    assert parse_waiver_expiry(3, {"expires_on": _PAST}, _TODAY, warnings) == (None, False)
    assert any("expired at 2020-01-01" in w for w in warnings), warnings
