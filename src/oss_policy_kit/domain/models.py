"""Core domain types for evaluation results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any


class ControlStatus(StrEnum):
    """Normalized outcome for a single control."""

    PASS = "pass"
    FAIL = "fail"
    MANUAL_REVIEW_REQUIRED = "manual-review-required"
    SELF_ATTESTED = "self-attested"
    NOT_EVALUATED = "not-evaluated"
    NOT_OBSERVABLE = "not-observable"
    NOT_APPLICABLE = "not-applicable"
    WAIVED = "waived"


class EvidenceCollectionMethod(StrEnum):
    """How evidence backing a control outcome was obtained."""

    LIVE = "live"
    MANUAL = "manual"
    STATIC = "static"


@dataclass(frozen=True, slots=True)
class LiveCollectionMetadata:
    """Metadata when live platform evidence collection was performed for a run."""

    performed: bool
    platform: str | None = None
    collected_at: str | None = None
    api_evidence_sources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EvalOutcome:
    """Raw outcome before catalog merge and waivers."""

    status: ControlStatus
    reason: str
    remediation: str
    evidence_sources: list[str]
    confidence: str
    evidence_collection_method: EvidenceCollectionMethod = EvidenceCollectionMethod.STATIC
    operational_warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WaiverRecord:
    """Versioned waiver applied during evaluation."""

    control_id: str
    justification: str
    owner: str
    status: str
    expires_at: date | None
    applies_to: list[str] | None


@dataclass(frozen=True, slots=True)
class ControlResult:
    """Single control evaluation row."""

    control_id: str
    title: str
    category: str
    status: ControlStatus
    profile: str
    evidence_sources: list[str]
    confidence: str
    reason: str
    remediation: str
    lifecycle: str = "stable"
    assurance: str = "signal"
    owner: str | None = None
    waiver: WaiverRecord | None = None
    expires_at: date | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    evidence_collection_method: str = "static"
    deprecation_note: str | None = None
    weight: int = 1


@dataclass(frozen=True, slots=True)
class WeightedScore:
    """Risk-adjusted posture score derived from control weights."""

    earned: int
    possible: int
    percent: float


@dataclass(frozen=True, slots=True)
class ExecutionReport:
    """Full evaluation run."""

    schema_version: str
    generated_at: str
    kit_version: str
    target_path: str
    profile_id: str
    profile_title: str
    summary_by_status: dict[str, int]
    results: list[ControlResult]
    operational_warnings: list[str]
    scorecard_path: str | None = None
    scorecard_supplemental: dict[str, Any] | None = None
    #: Absolute path to a waiver file passed via `--waivers` (not versioned in-repo policy).
    external_waiver_path: str | None = None
    live_collection: LiveCollectionMetadata | None = None
    weighted_score: WeightedScore | None = None


def utc_today() -> date:
    """Current UTC date for waiver expiry checks."""

    return datetime.now(UTC).date()
