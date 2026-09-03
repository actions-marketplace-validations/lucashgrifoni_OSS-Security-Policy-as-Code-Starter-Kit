"""Discover, parse, structurally validate, and project an OpenSSF Security
Insights file into recognized **self-reported** signals.

This is the single source of truth for Security Insights ingestion (ADR-032),
shared by two consumers:

- ``cli/ingest_insights.py`` — the read/validate/report subcommand.
- ``application/engine.py`` — the opt-in control-evidence wiring (ADR-033),
  behind ``--use-insights-evidence``, which lets a small allowlist of disclosure
  controls treat these self-reported fields as ``SELF_ATTESTED`` evidence.

The logic lives in the application layer (not the CLI) so the engine can consume
it without importing the delivery layer. It is clone-local and read-only; it
never fetches and never verifies the assertions — provenance is always
``self-reported``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from oss_policy_kit.application.input_limits import (
    BAD_INPUT_ERRORS,
    MAX_EVIDENCE_BYTES,
    bad_input_reason,
    read_text_capped,
    too_deep_reason,
)

#: Supported OpenSSF Security Insights schema version (the shape the kit knows).
INSIGHTS_SCHEMA_VERSION = "1.0.0"

#: Label for every refusal message about the ingested file, so one problem reads as one
#: explanation across ``ingest-insights`` and the ``--use-insights-evidence`` wiring.
_INPUT_LABEL = "Security Insights file"

#: Conventional locations for an OpenSSF Security Insights file, in lookup order.
#: Covers the spec-canonical ``SECURITY-INSIGHTS.yml`` (root and ``.github/``) and
#: the kit's own lowercase ``emit-insights`` default name.
INGEST_CANDIDATES: tuple[str, ...] = (
    "SECURITY-INSIGHTS.yml",
    "SECURITY-INSIGHTS.yaml",
    ".github/SECURITY-INSIGHTS.yml",
    ".github/SECURITY-INSIGHTS.yaml",
    "security-insights.yml",
    "security-insights.yaml",
    ".github/security-insights.yml",
    ".github/security-insights.yaml",
    "docs/SECURITY-INSIGHTS.yml",
)


def discover_insights_file(root: Path) -> Path | None:
    """Return the first existing Security Insights file under *root*, or None."""

    for rel in INGEST_CANDIDATES:
        p = root / rel
        if p.is_file():
            return p
    return None


def load_insights_file(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read + parse a Security Insights YAML file, refusing hostile input instead of crashing.

    Returns ``(doc, None)`` on success, or ``(None, error_message)`` when the file
    is unreadable, too deeply nested, not valid YAML, or not a YAML mapping. Oversize
    files raise ``InvalidInputError`` (CLI exit 2) via ``read_text_capped``.

    The nesting budget is checked explicitly, before parsing, exactly as the Scorecard
    reader does it (see ``input_limits.MAX_JSON_DEPTH``). Leaving it to ``RecursionError``
    is not enough and the difference is not theoretical here: the file is discovered
    *inside the repository under evaluation*, so a ~500-level ``SECURITY-INSIGHTS.yml``
    in an untrusted clone crashed ``evaluate --use-insights-evidence`` with exit 3 — a
    one-file denial of service against the gate, at a depth that depended on the
    interpreter's stack rather than on any documented limit. ``RecursionError`` stays in
    ``BAD_INPUT_ERRORS`` as the backstop for block-style YAML, whose depth is expressed
    by indentation and so carries no brackets for the scanner to count.
    """

    try:
        raw = read_text_capped(path, MAX_EVIDENCE_BYTES, label="Security Insights", errors="replace")
    except OSError as exc:
        # ``str(OSError)`` embeds the absolute filename; bad_input_reason cites the
        # bare name and the OS error text only (M-002).
        return None, bad_input_reason(exc, label=_INPUT_LABEL, name=path.name)
    too_deep = too_deep_reason(raw, label=f"{_INPUT_LABEL} '{path.name}'")
    if too_deep is not None:
        return None, too_deep
    try:
        doc = yaml.safe_load(raw)
    except BAD_INPUT_ERRORS as exc:
        return None, bad_input_reason(exc, label=_INPUT_LABEL, name=path.name)
    if not isinstance(doc, dict):
        return None, "Security Insights file root must be a YAML mapping (object)."
    return doc, None


def validate_ingest_structure(doc: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)`` for a parsed Security Insights document.

    Errors (exit 1) are missing required structure per the OpenSSF Security
    Insights 1.0 shape the kit knows. A declared ``schema-version`` other than the
    supported one is a *warning* (still summarizable), not an error — ingestion
    consumes third-party files and should not hard-fail a newer upstream version.
    """

    errors: list[str] = []
    warnings: list[str] = []
    if "project-lifecycle" not in doc:
        errors.append("top-level field missing: project-lifecycle")
    header = doc.get("header")
    if not isinstance(header, dict):
        errors.append("top-level field missing or not an object: header")
        return errors, warnings
    if "schema-version" not in header:
        errors.append("header.schema-version missing")
    if "last-updated" not in header:
        errors.append("header.last-updated missing")
    lifecycle = doc.get("project-lifecycle")
    if isinstance(lifecycle, dict) and "status" not in lifecycle:
        errors.append("project-lifecycle.status missing")
    sv = header.get("schema-version")
    if isinstance(sv, str) and sv != INSIGHTS_SCHEMA_VERSION:
        warnings.append(
            f"declared schema-version {sv!r} differs from the supported {INSIGHTS_SCHEMA_VERSION!r}; "
            "signals are summarized best-effort."
        )
    return errors, warnings


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _security_contacts(doc: dict[str, Any]) -> list[str]:
    """Collect self-reported security contacts (security-contacts[].value + email-contact)."""

    out: list[str] = []
    contacts = doc.get("security-contacts")
    if isinstance(contacts, list):
        for c in contacts:
            if isinstance(c, dict):
                v = _str_or_none(c.get("value"))
                if v and v not in out:
                    out.append(v)
    vr = doc.get("vulnerability-reporting")
    if isinstance(vr, dict):
        email = _str_or_none(vr.get("email-contact"))
        if email and email not in out:
            out.append(email)
    return out


def _distribution_points(doc: dict[str, Any]) -> list[str]:
    dp = doc.get("distribution-points")
    if not isinstance(dp, list):
        return []
    return [d for d in dp if isinstance(d, str) and d]


def extract_signals(doc: dict[str, Any]) -> dict[str, Any]:
    """Project the recognized self-reported fields into a flat signal summary."""

    lifecycle = doc.get("project-lifecycle")
    vr = doc.get("vulnerability-reporting")
    cp = doc.get("contribution-policy")
    return {
        "project_lifecycle_status": (_str_or_none(lifecycle.get("status")) if isinstance(lifecycle, dict) else None),
        "accepts_vulnerability_reports": (
            bool(vr.get("accepts-vulnerability-reports")) if isinstance(vr, dict) else None
        ),
        "security_policy_url": (_str_or_none(vr.get("security-policy")) if isinstance(vr, dict) else None),
        "security_contacts": _security_contacts(doc),
        "accepts_pull_requests": (bool(cp.get("accepts-pull-requests")) if isinstance(cp, dict) else None),
        "has_dependency_automation_policy": "dependencies" in doc,
        "distribution_points": _distribution_points(doc),
    }


@dataclass(frozen=True, slots=True)
class InsightsEvidence:
    """A discovered, parsed Security Insights file projected to self-reported signals.

    ``valid`` mirrors ``validate_ingest_structure`` (no structural errors). The
    control-evidence wiring (ADR-033) only consumes evidence from a structurally
    valid file; an invalid file contributes nothing.
    """

    source_rel: str
    valid: bool
    signals: dict[str, Any] = field(default_factory=dict)

    def declares_vulnerability_reporting_channel(self) -> bool:
        """True when the file self-declares an inbound vulnerability-reporting channel.

        Requires ``accepts-vulnerability-reports: true`` plus at least one channel
        (a ``security-policy`` URL or a security contact). This is the honest
        minimum the disclosure-control allowlist (GOV-DISC-013, CRA-ART14-COORD-002,
        GOV-DISC-065) accepts as a ``self-attested`` contribution (ADR-033).
        """

        if not self.valid:
            return False
        s = self.signals
        has_channel = bool(s.get("security_policy_url")) or bool(s.get("security_contacts"))
        return bool(s.get("accepts_vulnerability_reports")) and has_channel


def load_insights_evidence(repo_root: Path) -> InsightsEvidence | None:
    """Discover, parse, validate, and project a target's Security Insights file.

    Returns ``None`` when no file is found or it cannot be parsed (the wiring then
    contributes nothing and controls keep their clone-only verdict). Returns an
    ``InsightsEvidence`` (with ``valid`` reflecting structural validity) otherwise.
    Clone-local and read-only; never fetches.
    """

    chosen = discover_insights_file(repo_root)
    if chosen is None:
        return None
    doc, error = load_insights_file(chosen)
    if error is not None or doc is None:
        return None
    errors, _warnings = validate_ingest_structure(doc)
    try:
        source_rel = chosen.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:  # pragma: no cover - discovery only ever returns paths inside the repo
        # `relative_to` can only raise for a file outside `repo_root`, which
        # `discover_insights_file` does not produce. Kept so a future discovery that
        # follows a link records a basename rather than leaking an absolute path.
        source_rel = chosen.name
    return InsightsEvidence(source_rel=source_rel, valid=not errors, signals=extract_signals(doc))
