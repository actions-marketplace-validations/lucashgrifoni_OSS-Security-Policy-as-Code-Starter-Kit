"""Ingest an OpenSSF Scorecard v5.x JSON result as supplemental evidence (T2.3).

Single source of truth for the read-only ``ingest-scorecard`` CLI command. Loads a
Scorecard ``--format json`` result, maps each Scorecard *check* to the kit control it
corroborates, and reports the result plus its freshness.

Honesty model (consistent with ``docs/signal-controls-audit.md``): a Scorecard result
is **supplemental, inferred-trust signal** — it NEVER elevates a control's assurance
grade. A Scorecard-derived corroboration is ``inferred``, never ``verified`` /
``evidence-backed``. This command reports how an external Scorecard result lines up with
the kit's controls; it does not change any control's grade.

Scope discipline (the project is **not** a scanner engine): this records Scorecard's
own per-check scores and reasons **verbatim** — it never re-derives or recomputes a
check verdict, and it does not change any ``evaluate`` gate (symmetric with the
read-only ``ingest-insights`` consumer). The mapping is a fixed, documented crosswalk,
not a re-scoring step. See ``docs/scorecard-mapping.md``.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, checks_as_map, load_scorecard_auto

#: Max age (days) before a Scorecard result is considered stale for evidence-backing,
#: mirroring the kit's evidence-freshness convention used elsewhere (90 days).
EVIDENCE_MAX_AGE_DAYS: int = 90

#: Conservative, documented crosswalk: ``(scorecard_check, kit_control_id, note)``.
#: Each row ties an OpenSSF Scorecard check to the kit control it corroborates (the
#: single best-fit; the full per-check matrix lives in docs/scorecard-mapping.md).
#: ``note`` carries the OSPS criterion or a short purpose. Order is the display order.
#: This is a fixed mapping, never a re-scoring of the check.
SCORECARD_CONTROL_MAP: tuple[tuple[str, str, str], ...] = (
    ("Token-Permissions", "CI-PERM-006", "OSPS-AC-04 (least-privilege workflow tokens)"),
    ("Pinned-Dependencies", "CI-PIN-008", "OSPS-BR-01 (pinned third-party actions/deps)"),
    ("Dangerous-Workflow", "CI-DANGER-007", "dangerous workflow patterns"),
    ("Branch-Protection", "PLAT-BRPROT-015", "OSPS-AC-03 (default branch protection)"),
    ("Code-Review", "SLSA-SRC-004", "two-party review on protected branches"),
    ("Security-Policy", "GOV-SEC-001", "OSPS-VM-01 (security policy present)"),
    ("SAST", "SEC-CODEQL-010", "OSPS-VM-06 (static analysis in CI)"),
    ("Signed-Releases", "GH-PROV-023", "OSPS-BR-06 (release provenance/attestation)"),
    ("Vulnerabilities", "SAST-OSV-068", "known-vulnerability scanning"),
    ("Fuzzing", "SEC-FUZZ-001", "fuzzing harness present"),
    ("Dependency-Update-Tool", "DEP-UPDATE-001", "automated dependency updates"),
    ("License", "GOV-LIC-004", "license file present"),
)


@dataclasses.dataclass(frozen=True)
class MappedCheck:
    """One crosswalk row resolved against a loaded Scorecard result."""

    scorecard_check: str
    control_id: str
    note: str
    present: bool
    #: Scorecard's own check score (0-10, or -1 for inconclusive), recorded verbatim.
    score: int | None
    #: Scorecard's own check reason string, recorded verbatim.
    reason: str | None


@dataclasses.dataclass(frozen=True)
class ScorecardIngestReport:
    """Read-only summary of a Scorecard result mapped onto kit controls."""

    found: bool
    input_path: str | None
    result_date: str | None
    #: "fresh" | "stale" | "undated" — whole-result freshness vs EVIDENCE_MAX_AGE_DAYS.
    freshness: str
    aggregate_score: float | None
    mapped: tuple[MappedCheck, ...]

    @property
    def present_checks(self) -> tuple[MappedCheck, ...]:
        return tuple(m for m in self.mapped if m.present)

    @property
    def corroborated_controls(self) -> tuple[str, ...]:
        """Controls corroborated by a *fresh* Scorecard result (check present + fresh).

        This is supplemental, inferred-trust signal — it never elevates a control's
        assurance grade and changes no ``evaluate`` verdict (see
        ``docs/signal-controls-audit.md``). A stale or undated result corroborates nothing.
        """

        if self.freshness != "fresh":
            return ()
        return tuple(m.control_id for m in self.mapped if m.present)

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "input_path": self.input_path,
            "result_date": self.result_date,
            "freshness": self.freshness,
            "aggregate_score": self.aggregate_score,
            "corroborated_controls": list(self.corroborated_controls),
            "mapped_checks": [
                {
                    "scorecard_check": m.scorecard_check,
                    "control_id": m.control_id,
                    "note": m.note,
                    "present": m.present,
                    "score": m.score,
                    "reason": m.reason,
                }
                for m in self.mapped
            ],
        }


def _freshness(result_date: str | None, *, now: datetime, max_age_days: int) -> str:
    if not result_date:
        return "undated"
    try:
        dt = datetime.fromisoformat(result_date.replace("Z", "+00:00"))
    except ValueError:
        return "undated"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    age = (now - dt).days
    if age < 0:  # a future-dated result is treated as fresh, not stale
        return "fresh"
    return "fresh" if age <= max_age_days else "stale"


def build_report(
    bundle: ScorecardBundle,
    *,
    input_path: str | None,
    now: datetime,
    max_age_days: int = EVIDENCE_MAX_AGE_DAYS,
) -> ScorecardIngestReport:
    """Map a loaded Scorecard *bundle* onto the kit control crosswalk."""

    checks = checks_as_map(bundle)
    mapped = tuple(
        MappedCheck(
            scorecard_check=name,
            control_id=control_id,
            note=note,
            present=(check := checks.get(name.lower())) is not None,
            score=check.score if check is not None else None,
            reason=check.reason if check is not None else None,
        )
        for name, control_id, note in SCORECARD_CONTROL_MAP
    )
    return ScorecardIngestReport(
        found=True,
        input_path=input_path,
        result_date=bundle.result_date,
        freshness=_freshness(bundle.result_date, now=now, max_age_days=max_age_days),
        aggregate_score=bundle.aggregate_score,
        mapped=mapped,
    )


def ingest_scorecard(
    path: Path,
    *,
    now: datetime,
    max_age_days: int = EVIDENCE_MAX_AGE_DAYS,
) -> ScorecardIngestReport:
    """Load a Scorecard JSON/YAML result at *path* and build the ingest report.

    Raises whatever :func:`load_scorecard_auto` raises on an unreadable/invalid file;
    the CLI layer maps that to a clean exit code.
    """

    bundle = load_scorecard_auto(path)
    return build_report(bundle, input_path=str(path), now=now, max_age_days=max_age_days)
