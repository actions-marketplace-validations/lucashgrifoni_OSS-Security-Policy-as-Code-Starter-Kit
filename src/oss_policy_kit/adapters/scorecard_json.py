"""Optional ingestion of OpenSSF Scorecard JSON exports."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.infrastructure.yaml_io import load_yaml_file


@dataclass(slots=True)
class ScorecardCheck:
    """Normalized check entry."""

    name: str
    score: int | None
    reason: str | None = None


@dataclass(slots=True)
class ScorecardBundle:
    """Parsed Scorecard payload.

    ``aggregate_score`` is the official root ``score`` field (0-10) reported
    by the OpenSSF Scorecard CLI when present. Evaluators should prefer it
    over the arithmetic mean of check scores, which is not the same formula
    Scorecard uses internally.
    """

    checks: list[ScorecardCheck] = field(default_factory=list)
    raw_path: str | None = None
    aggregate_score: float | None = None
    #: The Scorecard run's ``date`` field (ISO-8601 string) when present, used for
    #: evidence-freshness/staleness checks by consumers. ``None`` when undated.
    result_date: str | None = None


def _coerce_checks(blob: Any) -> list[ScorecardCheck]:
    if blob is None:
        return []
    if isinstance(blob, dict) and "checks" in blob:
        blob = blob["checks"]
    if not isinstance(blob, list):
        return []
    out: list[ScorecardCheck] = []
    for item in blob:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        score = item.get("score")
        score_i = int(score) if isinstance(score, int) and not isinstance(score, bool) else None
        reason = item.get("reason") or item.get("details")
        reason_s = str(reason) if reason is not None else None
        out.append(ScorecardCheck(name=name, score=score_i, reason=reason_s))
    return out


def _coerce_aggregate_score(value: Any) -> float | None:
    """Return a well-formed Scorecard aggregate score in the 0-10 range."""

    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        score = float(value)
    else:
        return None
    if math.isnan(score):
        return None
    if score < 0.0 or score > 10.0:
        return None
    return score


def _coerce_date(value: Any) -> str | None:
    """Return a non-empty ISO-8601-ish date string, else ``None``."""

    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def load_scorecard_json(path: Path) -> ScorecardBundle:
    """Load Scorecard JSON (common CLI export shapes)."""

    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except UnicodeDecodeError as exc:
        # UTF-16/non-UTF-8 input: surface a clean LoadError (-> exit 2) instead of an exit-3
        # crash. OSError and json.JSONDecodeError keep propagating to the existing evaluate-path
        # handler (cli/common.py) which already renders the friendly "could not be parsed" message.
        raise LoadError(f"Scorecard JSON {path.name} could not be decoded as UTF-8: {exc}") from exc
    checks: list[ScorecardCheck] = []
    aggregate: float | None = None
    result_date: str | None = None
    if isinstance(data, dict):
        scorecard_obj = data.get("scorecard") if isinstance(data.get("scorecard"), dict) else None
        if scorecard_obj is not None:
            checks = _coerce_checks(scorecard_obj.get("checks"))
            aggregate = _coerce_aggregate_score(scorecard_obj.get("score"))
        if not checks:
            checks = _coerce_checks(data.get("checks"))
        if aggregate is None:
            aggregate = _coerce_aggregate_score(data.get("score"))
        result_date = _coerce_date(data.get("date"))
    return ScorecardBundle(
        checks=checks, raw_path=str(path.resolve()), aggregate_score=aggregate, result_date=result_date
    )


def load_scorecard_auto(path: Path) -> ScorecardBundle:
    """Load JSON or YAML scorecard-like file."""

    suf = path.suffix.lower()
    if suf in {".yaml", ".yml"}:
        data = load_yaml_file(path)
        checks = _coerce_checks(data if isinstance(data, dict) else None)
        aggregate: float | None = None
        result_date: str | None = None
        if isinstance(data, dict):
            aggregate = _coerce_aggregate_score(data.get("score"))
            if aggregate is None and isinstance(data.get("scorecard"), dict):
                aggregate = _coerce_aggregate_score(data["scorecard"].get("score"))
            result_date = _coerce_date(data.get("date"))
        return ScorecardBundle(
            checks=checks, raw_path=str(path.resolve()), aggregate_score=aggregate, result_date=result_date
        )
    return load_scorecard_json(path)


def checks_as_map(bundle: ScorecardBundle | None) -> dict[str, ScorecardCheck]:
    if bundle is None:
        return {}
    return {c.name.lower(): c for c in bundle.checks}
