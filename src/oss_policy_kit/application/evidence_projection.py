"""Evidence Model v2 projection for the reports/1.0 contract.

Maps a v4-era ``ControlResult`` (with flat ``evidence_sources``, free-form
``confidence``, scalar ``evidence_collection_method``) into the structured
``evidence`` object required by ``reports/1.0``.

Design rules (do not silently inflate trust):

- ``assurance: signal`` controls cannot be projected with ``trust_level: verified``.
  They become ``trust_level: inferred`` at best, even when ``status == pass``.
- ``api_collected`` evidence with a recent ``collected_at`` (default freshness
  window: 90 days) projects to ``trust_level: verified``; older than the window
  becomes ``stale`` and ``trust_level: declared``.
- ``user_supplied`` evidence with no ``attested_by`` metadata projects to
  ``self_attested`` and ``trust_level: declared``.
- ``not-observable`` and ``not-applicable`` statuses route to ``not_observable`` /
  ``not_applicable`` with ``trust_level: unobserved``.

This module is read-only with respect to evaluators: it only re-shapes the
already-computed ``ControlResult`` for the ``reports/1.0`` projection. Existing
``reports/0.x`` emission paths are unaffected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.models import (
    ControlResult,
    ControlStatus,
    utc_now,
)

EVIDENCE_PROVENANCE_VERSION = "evidence/2.0"

# Conservative default freshness window for API-collected platform evidence.
# Stale evidence on a hard-gate profile cannot back a `verified` trust level.
DEFAULT_FRESHNESS_WINDOW_DAYS = 90


def _is_placeholder_path(value: str) -> bool:
    v = value.strip().lower()
    if not v:
        return True
    return v in {"<placeholder>", "tbd", "todo", "n/a"}


_REDACTION_MARKER = "<redacted-absolute>"

# Evidence sources cross platforms (a report rendered on POSIX can carry Windows
# paths and vice versa), so separator handling never relies on the local os.sep.
_SEPARATOR_RE = re.compile(r"[\\/]+")
_DRIVE_RE = re.compile(r"[A-Za-z]:")


def _root_style(p: str) -> str | None:
    """Classify how ``p`` is rooted on a host, or ``None`` when it is repo-relative.

    Two consequences are deliberate rather than accidental:

    ``//host/path`` is read as a UNC share, not as a protocol-relative URL, and so
    collapses to the bare marker. Windows accepts forward slashes in UNC paths, so
    the alternative reading would let ``//internal-fileserver/share/audit.md`` ship
    verbatim. Losing an unusual reference is recoverable; publishing an internal
    server name is not. Only ``http://`` and ``https://`` are treated as URLs.

    A ``~``-rooted reference is redacted even though ``~`` hides the account name by
    construction, because what follows it still describes the layout of a private
    machine and the leaf is the only part a reader of a shared report can act on.
    """

    if p.startswith(("\\\\", "//")):
        # UNC share: the server and share names disclose internal infrastructure.
        return "unc"
    if p.startswith(("/", "~/")):
        return "posix"
    if p.startswith(("\\", "~\\")):
        return "windows"
    if _DRIVE_RE.fullmatch(p[:2]):
        return "windows"
    return None


def _home_chain() -> tuple[str, ...]:
    """Home-directory components below the filesystem root (``Users``, account name...)."""

    try:
        parts = Path.home().parts
    except (OSError, RuntimeError):  # pragma: no cover - only when HOME is unresolvable
        return ()
    return tuple(seg for seg in parts[1:] if seg)


def _starts_with_home_chain(p: str) -> bool:
    """True when a relative-looking path still leads with the real home directory.

    An upstream layer that strips only the drive letter turns a home path into
    something that no longer *looks* rooted while still carrying the account name.
    """

    chain = _home_chain()
    if not chain:
        return False
    parts = [seg for seg in _SEPARATOR_RE.split(p) if seg]
    if len(parts) < len(chain):
        return False
    return [seg.lower() for seg in parts[: len(chain)]] == [seg.lower() for seg in chain]


def _leaf_component(p: str, style: str) -> str:
    """Return the final path component, with host-identifying roots dropped first."""

    parts = [seg for seg in _SEPARATOR_RE.split(p) if seg and seg != "~"]
    if style == "unc":
        # \\server\share is host-identifying in its own right, never a usable leaf.
        parts = parts[2:]
    elif parts and _DRIVE_RE.fullmatch(parts[0]):
        parts = parts[1:]
    return parts[-1] if parts else ""


def _redact_path(path: str) -> tuple[str, bool]:
    """Best-effort: return (redacted_value, was_redacted).

    Redaction is decided by CONTENT — a host root (drive, UNC share, POSIX root) or
    the real home-directory chain — and keeps only the final component. Dropping a
    fixed NUMBER of leading components instead let any target nested deeper than that
    keep real host directory names, including the OS account name, in a reference the
    report labels ``"redacted": true``; a field that claims redaction and does not
    deliver it is worse than none, because a reviewer stops looking at it.

    Repo-relative sources (the common case) pass through untouched.
    """

    p = path.strip()
    if not p:
        return p, False
    style = _root_style(p)
    if style is None:
        if not _starts_with_home_chain(p):
            return p, False
        style = "windows" if "\\" in p else "posix"
    leaf = _leaf_component(p, style)
    # Historical output shapes are part of the report surface: POSIX roots render as
    # ``<redacted-absolute>file.md``, every other root as ``<redacted-absolute>/file.md``.
    separator = "" if style == "posix" else "/"
    return (f"{_REDACTION_MARKER}{separator}{leaf}" if leaf else _REDACTION_MARKER), True


def _classify_reference(value: str) -> dict[str, Any]:
    if value.lower().startswith(("http://", "https://")):
        return {"kind": "url", "value": value, "redacted": False}
    redacted_value, was_redacted = _redact_path(value)
    return {"kind": "path", "value": redacted_value, "redacted": was_redacted}


def classify_reference(value: str) -> dict[str, Any]:
    """Public wrapper over :func:`_classify_reference`.

    The Markdown report (M-002) reuses the same evidence-reference redaction the
    JSON report already applies, so a shareable ``.md`` never leaks an absolute
    path that the JSON path would have redacted.
    """

    return _classify_reference(value)


@dataclass(frozen=True, slots=True)
class FreshnessContext:
    """Optional freshness window override (mostly for tests and CLI flags)."""

    window_days: int = DEFAULT_FRESHNESS_WINDOW_DAYS


def _parse_collected_at(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        # Accept naive ISO8601 and assume UTC if missing tz.
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _freshness_status(
    *,
    method: str,
    collected_at: datetime | None,
    has_evidence: bool,
    ctx: FreshnessContext,
) -> str:
    if not has_evidence:
        return "not_applicable"
    if method == "static":
        # Clone-visible facts do not have a meaningful freshness window.
        return "not_applicable"
    if collected_at is None:
        return "unknown"
    now = utc_now()
    if now - collected_at > timedelta(days=ctx.window_days):
        return "stale"
    return "fresh"


def _source_type_from_result(result: ControlResult) -> str:
    """Classify the source type from existing ControlResult fields."""

    if result.status == ControlStatus.NOT_OBSERVABLE:
        return "not_observable"
    if result.status == ControlStatus.NOT_APPLICABLE:
        return "not_observable"
    if result.status == ControlStatus.MANUAL_REVIEW_REQUIRED:
        return "manual_review"

    method = (result.evidence_collection_method or "static").lower()
    if method == "live":
        return "api_collected"
    if method == "manual":
        return "user_supplied"

    # method == "static" (clone-visible)
    if result.assurance == "signal":
        return "heuristic_signal"
    if result.assurance == "evidence-backed":
        # Static evidence-backed paths exist (placeholder JSON in repo, etc.)
        return "user_supplied"
    return "static_clone"


def _attestation_status_from_result(result: ControlResult, source_type: str) -> str:
    if source_type in {"not_observable", "manual_review"}:
        return "not_applicable"
    extra_attested = bool(result.extra.get("attested_by")) if isinstance(result.extra, dict) else False
    if source_type == "api_collected" and extra_attested:
        return "signed"
    if source_type in {"user_supplied", "api_collected"}:
        return "self_attested"
    return "none"


def _trust_level(
    *,
    result: ControlResult,
    source_type: str,
    freshness: str,
    attestation: str,
) -> str:
    """Project trust_level under the no-silent-inflation rules."""

    if result.status == ControlStatus.NOT_OBSERVABLE:
        return "unobserved"
    if result.status in (ControlStatus.NOT_APPLICABLE, ControlStatus.NOT_EVALUATED):
        return "unobserved"
    if result.status == ControlStatus.MANUAL_REVIEW_REQUIRED:
        return "inferred"

    if source_type == "heuristic_signal":
        return "inferred"
    if source_type == "static_clone":
        return "declared"
    if source_type == "user_supplied":
        return "declared"
    if source_type == "api_collected":
        # Only a fresh, attested collection is verified. Everything else -- stale, unattested,
        # or freshness we could not establish -- lands on "declared" alike, so there is no
        # separate stale branch to take: it returned the same value as the fall-through.
        if freshness == "fresh" and attestation in {"signed", "self_attested"}:
            return "verified"
        return "declared"
    if source_type == "derived":
        return "inferred"
    return "unobserved"


def _gate_role(status: ControlStatus) -> str:
    return {
        ControlStatus.PASS: "passed_observation",
        # ATTESTED (ADR-028) is a pass at the CI-gate dimension (does not block); the
        # assurance distinction vs. plain PASS is carried by the per-control status field.
        ControlStatus.ATTESTED: "passed_observation",
        ControlStatus.FAIL: "ci_blocking_fail",
        ControlStatus.MANUAL_REVIEW_REQUIRED: "human_review_gate",
        ControlStatus.SELF_ATTESTED: "self_attested_declarative",
        ControlStatus.NOT_EVALUATED: "not_evaluated_limit",
        ControlStatus.WAIVED: "waived",
        ControlStatus.NOT_APPLICABLE: "not_applicable",
        ControlStatus.NOT_OBSERVABLE: "not_observable",
    }[status]


def _limitations(*, source_type: str, freshness: str, attestation: str, assurance: str) -> list[str]:
    out: list[str] = []
    if source_type == "heuristic_signal":
        out.append("Result is backed by keyword/heuristic matches; absence of match is not absence of control.")
    if source_type == "user_supplied" and attestation in {"self_attested", "none"}:
        out.append("Evidence is self-attested by the maintainer, not platform-verified.")
    if freshness == "stale":
        out.append("Evidence freshness window exceeded; re-collect before relying on this result for a release gate.")
    if freshness == "unknown":
        out.append("Evidence has no collection timestamp; freshness cannot be asserted.")
    if assurance == "signal":
        out.append("Catalog assurance is 'signal'; trust_level cannot exceed 'inferred' for this control.")
    return out


def _source_platform_from_result(result: ControlResult) -> str | None:
    """Return the evidence source platform from ``result.extra`` or a control-id prefix heuristic."""

    if isinstance(result.extra, dict):
        plat = result.extra.get("source_platform") or result.extra.get("platform")
        if isinstance(plat, str) and plat.strip():
            return plat.strip()
    cid = result.control_id
    if cid.startswith("AZ-"):
        return "azure"
    if cid.startswith("AWS-"):
        return "aws"
    if cid.startswith(("GH-", "PLAT-", "CI-", "GOV-", "REL-", "SEC-")):
        return "github" if cid.startswith(("GH-", "PLAT-")) else "local"
    return None


def _digest_and_schema_from_result(result: ControlResult) -> tuple[str | None, str | None]:
    """Extract the ``sha256:`` digest and evidence schema id from ``result.extra`` if present."""

    if not isinstance(result.extra, dict):
        return None, None
    d = result.extra.get("digest")
    digest = d if isinstance(d, str) and d.startswith("sha256:") else None
    sid = result.extra.get("evidence_schema_id")
    schema_id = sid.strip() if isinstance(sid, str) and sid.strip() else None
    return digest, schema_id


def project_evidence(result: ControlResult, *, ctx: FreshnessContext | None = None) -> dict[str, Any]:
    """Project a ControlResult into the v1 ``evidence`` object."""

    ctx = ctx or FreshnessContext()
    source_type = _source_type_from_result(result)
    method = (result.evidence_collection_method or "static").lower()
    if method not in {"live", "manual", "static"}:
        method = "static"

    collected_at_raw: str | None = None
    if isinstance(result.extra, dict):
        collected_at_raw = result.extra.get("collected_at") or result.extra.get("collection_collected_at")

    collected_at_dt = _parse_collected_at(collected_at_raw)
    has_evidence = bool(result.evidence_sources) or source_type in {"api_collected", "user_supplied"}
    freshness = _freshness_status(
        method=method,
        collected_at=collected_at_dt,
        has_evidence=has_evidence,
        ctx=ctx,
    )
    attestation = _attestation_status_from_result(result, source_type)
    trust = _trust_level(
        result=result,
        source_type=source_type,
        freshness=freshness,
        attestation=attestation,
    )

    references = [_classify_reference(s) for s in result.evidence_sources if not _is_placeholder_path(s)]
    source_platform = _source_platform_from_result(result)
    limitations = _limitations(
        source_type=source_type,
        freshness=freshness,
        attestation=attestation,
        assurance=result.assurance,
    )
    digest, schema_id = _digest_and_schema_from_result(result)

    return {
        "source_type": source_type,
        "trust_level": trust,
        "collection_method": method,
        "collected_at": collected_at_raw,
        "source_platform": source_platform,
        "freshness_status": freshness,
        "attestation_status": attestation,
        "references": references,
        "limitations": limitations,
        "digest": digest,
        "evidence_schema_id": schema_id,
    }


def gate_role_for(status: ControlStatus) -> str:
    """Public helper exposing the status -> gate_role mapping."""

    return _gate_role(status)
