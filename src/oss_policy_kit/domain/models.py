"""Core domain types for evaluation results."""

from __future__ import annotations

import os
import unicodedata
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
    # ATTESTED (ADR-028, v8.x): a passing verdict anchored on a *verified* attestation
    # (in-toto + cosign keyless), distinct from SELF_ATTESTED (maintainer self-claim) and
    # from a deterministic PASS. Emitted by PROV-VERIFY-061 and GH-IMMUTREL-070, and
    # `evaluate --enable-attested` defaults to on since v8.0.0 (ADR-041), so a stock run
    # reaches it whenever the verification record is complete and fresh.
    ATTESTED = "attested"
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
    #: Optional per-control metadata projected onto ``ControlResult.extra`` (e.g.
    #: ``{"provenance": "self-reported"}`` for ADR-033 Insights-derived verdicts).
    #: Default empty so existing evaluators are unaffected.
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class WaiverRecord:
    """Versioned waiver applied during evaluation."""

    control_id: str
    justification: str
    owner: str
    status: str
    expires_at: date | None
    applies_to: list[str] | None


#: The confidence vocabulary a control result may hold, and the free-form spellings that
#: map into it. It lives here, beside :class:`ControlStatus`, because it is a domain
#: vocabulary: an evaluator -- including a third-party one -- returns a string, and every
#: artifact has to agree on what that string means.
_CONFIDENCE_NORMALIZATION: dict[str, str] = {
    "high": "high",
    "strong": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "weak": "low",
    "none": "none",
    "n/a": "none",
    "not-applicable": "none",
    "not_applicable": "none",
}


def normalize_confidence(raw: str | None) -> str:
    """Map free-form ``confidence`` strings into the v1 enum.

    An unrecognized value becomes ``low`` rather than being passed through: the kit does
    not know what a plugin's own word means, and reporting a confidence it cannot place
    as anything but the weakest one would be a claim about evidence strength.

    Idempotent -- every value in the enum maps to itself -- which is what lets
    :class:`ControlResult` apply it once at construction.
    """

    if not raw:
        return "none"
    return _CONFIDENCE_NORMALIZATION.get(raw.strip().lower(), "low")


#: Unicode general categories that carry no glyph: Cc (control) and Cf (format -- bidi
#: overrides, zero-width joiners, the byte-order mark).
_INVISIBLE = frozenset({"Cc", "Cf"})


#: Kept even though they are control characters: they are whitespace a reason may legitimately
#: contain, and the Markdown writer folds them itself so a row cannot be split.
_KEEPABLE_CONTROLS = frozenset("\t\n\r")


def without_control_characters(value: str) -> str:
    """Drop invisible and terminal-controlling characters from human-facing report text.

    Control text reaches a report from the audited repository: ``CI-LEAST-009`` interpolates a
    workflow's job NAME into its reason, and a job name is a YAML key the target chooses. A
    workflow declaring ``"build\\e[31m INJECTED \\e[0m"`` is a legal document -- the file holds
    the printable escape, YAML decodes it -- and the escape reached
    ``evaluation-report.md`` raw, which is a file people ``cat``, paste into a pull request,
    and attach to releases. From there it colours, moves the cursor, or with ``\\e[2K\\r``
    overwrites the line already printed, so the target repository decides what its own security
    report appears to say.

    Format characters go too, and they are the sharper half: U+202E RIGHT-TO-LEFT OVERRIDE
    reverses the display order of everything after it (the Trojan Source trick) and U+200B is
    invisible. Both reached the **JSON** report as raw characters as well, because ``json.dumps``
    escapes C0 controls but leaves other categories alone under ``ensure_ascii=False``.

    Tab, newline and carriage return survive: they are whitespace, and the Markdown writer
    already folds them so they cannot break a table row.
    """

    if value.isprintable():
        return value
    return "".join(ch for ch in value if ch in _KEEPABLE_CONTROLS or unicodedata.category(ch) not in _INVISIBLE)


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

    def __post_init__(self) -> None:
        """Clean the prose fields and settle the confidence here, not at each writer.

        ``reason`` and ``remediation`` are the two an evaluator builds by interpolating
        something the target repository wrote, and every artifact -- JSON, Markdown, SARIF,
        the terminal -- renders them from this one object. Cleaning at the writers means
        four places to keep in step and a fifth writer arriving unprotected; cleaning here
        means no ``ControlResult`` can hold an invisible character at all.

        ``confidence`` is settled here for the same reason, and it had already drifted: the
        JSON and the SARIF normalized it while the Markdown and the terminal printed the
        evaluator's raw string, so one run produced artifacts that disagreed about the same
        field. An evaluator answering ``"Strong"`` was reported as ``high`` in two of them
        and ``Strong`` in the other two; one answering something the kit cannot place was
        reported as ``low`` in two and verbatim in the other two -- the conservative
        fallback in one artifact and the unexamined claim in the next.

        The two writers that normalized on their own no longer do. A second call would be
        a no-op no test could tell apart from its absence, and a guard nothing can falsify
        is decoration.
        """

        for attribute in ("title", "reason", "remediation"):
            value = getattr(self, attribute)
            object.__setattr__(self, attribute, without_control_characters(value))
        object.__setattr__(self, "confidence", normalize_confidence(self.confidence))


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


def utc_now() -> datetime:
    """Current UTC datetime, honouring ``SOURCE_DATE_EPOCH`` (reproducible builds).

    Every clock read that can change an evaluation OUTCOME (evidence freshness,
    waiver expiry, attestation-freshness windows) flows through this helper so a
    reproducible-build environment — or the test suite — can pin the evaluation
    date via the standard ``SOURCE_DATE_EPOCH`` environment variable. With the
    variable unset, behaviour is unchanged (``datetime.now(UTC)``).
    """

    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw:
        try:
            epoch = int(raw.strip())
        except ValueError:
            epoch = -1
        if epoch >= 0:
            return datetime.fromtimestamp(epoch, tz=UTC)
    return datetime.now(UTC)


def utc_today() -> date:
    """Current UTC date for waiver expiry checks (honours ``SOURCE_DATE_EPOCH``)."""

    return utc_now().date()
