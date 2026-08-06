"""Waivers must fail closed on a non-active status and on a malformed expiry.

Two fail-open classes are covered here:

* status — a vulnerability-keyed waiver whose ``status`` is ``pending``,
  ``rejected``, ``revoked``, ``denied`` or ``withdrawn`` used to suppress the
  finding anyway, so a waiver that was never granted (or was taken away) still
  exempted a KEV/critical finding from ``--fail-on-*`` and turned a red gate
  green.
* expires_at — a non-string expiry (an integer, or the YAML boolean that an
  unquoted ``yes``/``no`` produces) used to be read as "no expiry at all", so a
  one-character typo silently promoted an expired waiver to a permanent one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.vuln_waivers import load_vuln_waivers
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()

NON_ACTIVE_STATUSES = ["pending", "rejected", "revoked", "denied", "withdrawn", "draft", "expired"]


def _waivers(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "waivers.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _vuln_entry(*, status: str | None = None, expires_at: str | None = None) -> str:
    lines = [
        "waivers:",
        "  - vulnerability_ids: [CVE-2026-1]",
        "    owner: appsec",
        "    justification: reviewed, not reachable",
    ]
    if status is not None:
        lines.append(f"    status: {status}")
    if expires_at is not None:
        lines.append(f"    expires_at: {expires_at}")
    return "\n".join(lines) + "\n"


def _control_entry(*, status: str | None = None, expires_at: str | None = None) -> str:
    lines = [
        "waivers:",
        "  - control_id: GOV-SEC-001",
        "    owner: appsec",
        "    justification: reviewed, compensating control in place",
    ]
    if status is not None:
        lines.append(f"    status: {status}")
    if expires_at is not None:
        lines.append(f"    expires_at: {expires_at}")
    return "\n".join(lines) + "\n"


def _write_osv(repo: Path) -> None:
    """A single KEV-flagged critical finding, enough to trip both --fail-on-* gates."""

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "osv-scanner", "version": "2.0.0"}},
                "results": [
                    {
                        "ruleId": "CVE-2026-1",
                        "level": "error",
                        "message": {"text": "vulnerable dep"},
                        "properties": {"kev": "true", "cve": "CVE-2026-1"},
                    }
                ],
            }
        ],
    }
    path = repo / ".oss-policy-kit" / "evidence" / "sast" / "osv-scanner.sarif.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


# --------------------------------------------------------------------------- #
# status — only an explicitly active status may waive
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", NON_ACTIVE_STATUSES)
def test_non_active_vuln_waiver_status_does_not_waive(status: str, tmp_path: Path) -> None:
    """A waiver that was never granted (or was revoked) must not suppress the finding."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, _vuln_entry(status=status)))
    assert mapping == {}
    assert any(status in w and "status" in w for w in warnings), warnings


def test_unrecognised_vuln_waiver_status_fails_closed(tmp_path: Path) -> None:
    """An unknown status word is not a licence to waive; the reason must be visible."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, _vuln_entry(status="aproved")))
    assert mapping == {}
    assert any("aproved" in w for w in warnings), warnings


def test_non_string_vuln_waiver_status_fails_closed(tmp_path: Path) -> None:
    """An unquoted YAML boolean status is a typo, not an approval."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, _vuln_entry(status="yes")))
    assert mapping == {}
    assert warnings


@pytest.mark.parametrize("status", ["approved", "active", "APPROVED", " approved "])
def test_active_vuln_waiver_status_still_waives(status: str, tmp_path: Path) -> None:
    """The legitimate approval path is untouched (case/whitespace tolerant)."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, _vuln_entry(status=f'"{status}"')))
    assert "CVE-2026-1" in mapping
    assert warnings == []


def test_absent_vuln_waiver_status_keeps_documented_default(tmp_path: Path) -> None:
    """An omitted status keeps the documented 'approved' default (contract-preserving)."""

    mapping, _ = load_vuln_waivers(_waivers(tmp_path, _vuln_entry()))
    assert "CVE-2026-1" in mapping


def test_revoked_vuln_waiver_does_not_exempt_the_findings_gate(tmp_path: Path) -> None:
    """End-to-end: a revoked waiver must leave `correlate-findings --fail-on-kev` red."""

    _write_osv(tmp_path)
    _waivers(tmp_path, _vuln_entry(status="revoked", expires_at='"2099-12-31"'))
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "correlate-findings",
                "--target",
                str(tmp_path),
                "--output",
                str(out),
                "--fail-on-kev",
                "--waivers",
                "waivers.yaml",
            ]
        ),
    )
    assert result.exit_code == 1, result.output
    artifact = json.loads(out.read_text(encoding="utf-8"))
    finding = next(f for f in artifact["findings"] if "CVE-2026-1" in f["vulnerability_ids"])
    assert finding["waiver"]["waived"] is False
    assert artifact["extensions"]["waiver_warnings"]


def test_non_active_control_waiver_status_is_reported(tmp_path: Path) -> None:
    """A pending control-gate waiver is dropped loudly, not silently ignored downstream."""

    outcome = parse_waivers_file(_waivers(tmp_path, _control_entry(status="pending", expires_at='"2099-12-31"')))
    assert "GOV-SEC-001" not in outcome.by_control
    assert any("pending" in w for w in outcome.warnings), outcome.warnings


# --------------------------------------------------------------------------- #
# expires_at — a malformed expiry never means "no expiry"
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("expires_at", ["20991231", "yes", "no", "true", "1.5", "[2099-12-31]"])
def test_non_string_vuln_waiver_expiry_never_means_permanent(expires_at: str, tmp_path: Path) -> None:
    """A typo'd expiry must not silently promote the waiver to one that never expires."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, _vuln_entry(expires_at=expires_at)))
    assert mapping == {}
    assert any("expires_at" in w for w in warnings), warnings


def test_yaml_timestamp_vuln_waiver_expiry_still_expires(tmp_path: Path) -> None:
    """An unquoted YAML timestamp in the past is expired, not permanent."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, _vuln_entry(expires_at="2020-01-01 10:00:00")))
    assert mapping == {}
    assert any("expired" in w.lower() for w in warnings), warnings


def test_yaml_timestamp_vuln_waiver_expiry_in_future_is_kept(tmp_path: Path) -> None:
    """The same timestamp shape in the future is honored, keeping the date value."""

    mapping, warnings = load_vuln_waivers(_waivers(tmp_path, _vuln_entry(expires_at="2099-01-02 10:00:00")))
    assert "CVE-2026-1" in mapping
    assert mapping["CVE-2026-1"].expires_at is not None
    assert mapping["CVE-2026-1"].expires_at.isoformat() == "2099-01-02"
    assert warnings == []


@pytest.mark.parametrize("expires_at", ["20991231", "yes", "no", "true", "1.5", "[2099-12-31]"])
def test_non_string_control_waiver_expiry_never_means_permanent(expires_at: str, tmp_path: Path) -> None:
    """Same typo on the control-gate path must not create a permanent waiver either."""

    outcome = parse_waivers_file(_waivers(tmp_path, _control_entry(expires_at=expires_at)))
    assert "GOV-SEC-001" not in outcome.by_control
    assert any("expires_at" in w for w in outcome.warnings), outcome.warnings


def test_legacy_expires_on_non_string_also_fails_closed(tmp_path: Path) -> None:
    """The legacy ``expires_on`` spelling gets the same type discipline."""

    src = "waivers:\n  - control_id: GOV-SEC-001\n    owner: appsec\n    justification: reviewed\n    expires_on: yes\n"
    outcome = parse_waivers_file(_waivers(tmp_path, src))
    assert "GOV-SEC-001" not in outcome.by_control
    assert outcome.warnings


def test_valid_string_and_date_expiries_are_unaffected(tmp_path: Path) -> None:
    """Regression fence: the two legitimate expiry spellings keep working."""

    quoted = parse_waivers_file(_waivers(tmp_path, _control_entry(expires_at='"2099-12-31"')))
    assert quoted.by_control["GOV-SEC-001"].expires_at is not None
    plain = parse_waivers_file(_waivers(tmp_path, _control_entry(expires_at="2099-12-31")))
    assert plain.by_control["GOV-SEC-001"].expires_at is not None
