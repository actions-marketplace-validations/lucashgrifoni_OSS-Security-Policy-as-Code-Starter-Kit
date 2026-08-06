"""Vulnerability-keyed waiver parsing shared by emit-vex and correlate-findings (A-S7).

Hoisted verbatim from ``cli/emit_vex.py`` (v10.0.0) so both surfaces read the
same ``waivers/waivers.yaml`` entries that carry a ``vulnerability_ids: [...]``
field. Distinct from the control-keyed :class:`WaiverRecord` path that steers
the ``evaluate`` gate — a vulnerability-keyed waiver NEVER changes any control
state, ``summary_by_status``, or ``results_digest`` (fence FT-3): its effect is
confined to the VEX document, the findings/1.0 waiver blocks, and the
findings-surface ``--fail-on-*`` gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.models import utc_today
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file

#: Waiver statuses that actually authorize suppression. Mirrors the control-gate
#: set in ``application.engine._apply_waiver``: a waiver that is pending, rejected,
#: revoked, withdrawn — or simply misspelled — was never granted, so it must not
#: suppress a finding or exempt it from the findings-surface ``--fail-on-*`` gates.
ACTIVE_WAIVER_STATUSES: frozenset[str] = frozenset({"approved", "active"})

#: Applied only when a waiver entry omits ``status`` entirely (documented default).
DEFAULT_WAIVER_STATUS = "approved"

_EXPECTED_STATUSES = ", ".join(sorted(ACTIVE_WAIVER_STATUSES))

#: CycloneDX 1.6 allowed enum values for analysis.justification.
CDX_JUSTIFICATIONS: frozenset[str] = frozenset(
    {
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compensating_control",
        "inline_mitigations_already_exist",
    }
)


@dataclass(frozen=True, slots=True)
class VulnWaiver:
    """Per-vulnerability waiver entry from waivers/waivers.yaml.

    Distinct from the kit's main ``WaiverRecord`` (which is keyed by
    ``control_id``). Extending this shape never touches the evaluation engine.
    """

    justification_text: str
    owner: str
    status: str  # always an ACTIVE_WAIVER_STATUSES value: non-active entries never become a record
    expires_at: date | None
    cdx_justification: str | None  # one of CDX_JUSTIFICATIONS or None


def parse_waiver_expiry(idx: int, item: dict[str, Any], today: date, warnings: list[str]) -> tuple[date | None, bool]:
    """Return ``(expires_at, ok)``; ``ok`` is False when the entry should be skipped (bad/expired).

    Only an absent (or explicitly null) ``expires_at`` means "no expiry". A value
    that is present but not a date — an integer, a float, or the boolean YAML
    produces for an unquoted ``yes``/``no`` — is a typo, and reading it as "never
    expires" would silently turn an expired waiver into a permanent one.
    """

    if "expires_at" not in item:
        return None, True
    raw = item["expires_at"]
    if raw is None:
        return None, True
    expires_at: date | None
    if isinstance(raw, str):
        expires_at = _expiry_from_text(idx, raw, warnings)
        if expires_at is None:
            return None, False
    elif isinstance(raw, datetime):
        expires_at = raw.date()
    elif isinstance(raw, date):
        expires_at = raw
    else:
        warnings.append(
            f"Waiver entry {idx} ignored: expires_at={raw!r} is not a date; "
            'quote it as "YYYY-MM-DD" (a malformed expiry is never read as "no expiry").'
        )
        return None, False
    if expires_at < today:
        warnings.append(f"Waiver entry {idx} ignored: expired at {expires_at.isoformat()}.")
        return None, False
    return expires_at, True


def _expiry_from_text(idx: int, raw: str, warnings: list[str]) -> date | None:
    """Parse a textual ``expires_at``; None (with a warning) when it is blank or unparseable."""

    text = raw.strip()
    if not text:
        warnings.append(f"Waiver entry {idx} ignored: expires_at is blank; use a date or drop the field.")
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        warnings.append(f"Waiver entry {idx} has unparseable expires_at={raw!r}; ignored.")
        return None


def parse_waiver_status(idx: int, item: dict[str, Any], warnings: list[str]) -> str | None:
    """Return the normalized active status, or None when the entry must not waive.

    An omitted ``status`` keeps the documented ``approved`` default; a status that
    is present must be explicitly active, so pending / rejected / revoked — and
    anything unrecognised — fails closed with a visible reason.
    """

    if "status" not in item:
        return DEFAULT_WAIVER_STATUS
    raw = item["status"]
    if not isinstance(raw, str):
        warnings.append(
            f"Waiver entry {idx} ignored: status={raw!r} is not a status word (expected one of {_EXPECTED_STATUSES})."
        )
        return None
    status = raw.strip().lower()
    if status not in ACTIVE_WAIVER_STATUSES:
        warnings.append(
            f"Waiver entry {idx} ignored: status={raw!r} does not authorize a waiver "
            f"(expected one of {_EXPECTED_STATUSES})."
        )
        return None
    return status


def parse_cdx_justification(idx: int, item: dict[str, Any], warnings: list[str]) -> str | None:
    """Validate the optional CycloneDX VEX justification enum value."""

    cdx_just = item.get("vex_justification")
    if not isinstance(cdx_just, str):
        return None
    cdx_just = cdx_just.strip()
    if cdx_just not in CDX_JUSTIFICATIONS:
        warnings.append(
            f"Waiver entry {idx} has vex_justification={cdx_just!r} not in CycloneDX enum; field will be omitted."
        )
        return None
    return cdx_just


def parse_vuln_waiver_entry(
    idx: int, item: Any, today: date, warnings: list[str]
) -> tuple[list[Any], VulnWaiver] | None:
    """Parse one waiver entry into ``(vulnerability_ids, record)`` or None when it should be skipped."""

    if not isinstance(item, dict):
        return None
    vuln_ids = item.get("vulnerability_ids")
    if not isinstance(vuln_ids, list) or not vuln_ids:
        return None  # control-id-only waiver — not our concern here
    justification = str(item.get("justification", "")).strip()
    if not justification:
        warnings.append(f"Waiver entry {idx} ignored: empty justification.")
        return None
    owner = str(item.get("owner", "")).strip()
    if not owner:
        warnings.append(f"Waiver entry {idx} ignored: empty owner.")
        return None
    status = parse_waiver_status(idx, item, warnings)
    if status is None:
        return None
    expires_at, ok = parse_waiver_expiry(idx, item, today, warnings)
    if not ok:
        return None
    record = VulnWaiver(
        justification_text=justification,
        owner=owner,
        status=status,
        expires_at=expires_at,
        cdx_justification=parse_cdx_justification(idx, item, warnings),
    )
    return vuln_ids, record


def load_vuln_waivers(path: Path) -> tuple[dict[str, VulnWaiver], list[str]]:
    """Return (vulnerability_id → waiver, warnings).

    Reads ``waivers/waivers.yaml`` (or the supplied path) and collects only
    entries that carry a ``vulnerability_ids: [...]`` field. Entries that key
    on ``control_id`` alone are ignored — they steer the evaluation gate, not
    the VEX document or the findings surface.
    """

    warnings: list[str] = []
    if not path.is_file():
        return {}, warnings
    try:
        raw = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001
        # basename only: the warning lands verbatim in the shareable findings/1.0
        # extensions.waiver_warnings; never leak the absolute path / username (M-002).
        warnings.append(f"Could not read waivers file {path.name}: {exc}")
        return {}, warnings
    if not isinstance(raw, dict):
        warnings.append(f"Waivers file {path.name} is not a YAML mapping; ignoring.")
        return {}, warnings
    entries = raw.get("waivers")
    if not isinstance(entries, list):
        if "waivers" in raw:
            warnings.append(f"Waivers file {path.name} 'waivers' is not a list; ignored.")
        return {}, warnings
    today = utc_today()
    out: dict[str, VulnWaiver] = {}
    for idx, item in enumerate(entries):
        parsed = parse_vuln_waiver_entry(idx, item, today, warnings)
        if parsed is None:
            continue
        vuln_ids, record = parsed
        for v in vuln_ids:
            if isinstance(v, str) and v.strip():
                out[v.strip()] = record
    return out, warnings
