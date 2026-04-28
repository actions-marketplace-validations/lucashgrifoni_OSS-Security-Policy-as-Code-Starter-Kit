"""Compare two evaluation reports for posture drift."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ControlDelta:
    """Single control posture change between two reports."""

    control_id: str
    title: str
    before_status: str
    after_status: str
    is_regression: bool


@dataclass
class DriftReport:
    """Aggregated drift between two evaluation JSON payloads."""

    before_path: str
    after_path: str
    before_kit_version: str
    after_kit_version: str
    regressions: list[ControlDelta] = field(default_factory=list)
    improvements: list[ControlDelta] = field(default_factory=list)
    new_controls: list[str] = field(default_factory=list)
    removed_controls: list[str] = field(default_factory=list)
    expired_waivers: list[str] = field(default_factory=list)
    has_regressions: bool = False
    profile_mismatch: bool = False
    before_profile_id: str | None = None
    after_profile_id: str | None = None


def _result_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = report.get("results")
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict):
            cid = str(row.get("control_id", "")).strip()
            if cid:
                out[cid] = row
    return out


def _title(row: dict[str, Any]) -> str:
    return str(row.get("title", ""))


def _status(row: dict[str, Any]) -> str:
    return str(row.get("status", ""))


def _is_positive(status: str) -> bool:
    return status in {"pass", "self-attested"}


def _is_negative(status: str) -> bool:
    return status == "fail"


def compute_drift(before: dict[str, Any], after: dict[str, Any]) -> DriftReport:
    """Compute the drift between two evaluation reports.

    Args:
        before: Parsed JSON of the earlier ``evaluation-report.json``.
        after: Parsed JSON of the more recent ``evaluation-report.json``.

    Returns:
        :class:`DriftReport` describing posture changes, regressions, and improvements.
    """

    before_path = str(before.get("_path", ""))
    after_path = str(after.get("_path", ""))
    before_kv = str(before.get("kit_version", ""))
    after_kv = str(after.get("kit_version", ""))
    before_profile = before.get("profile_id")
    after_profile = after.get("profile_id")
    before_pid = str(before_profile).strip() if before_profile is not None else None
    after_pid = str(after_profile).strip() if after_profile is not None else None
    profile_mismatch = bool(
        before_pid is not None
        and before_pid != ""
        and after_pid is not None
        and after_pid != ""
        and before_pid != after_pid
    )
    bm = _result_map(before)
    am = _result_map(after)
    before_ids = set(bm)
    after_ids = set(am)

    regressions: list[ControlDelta] = []
    improvements: list[ControlDelta] = []
    new_controls = sorted(after_ids - before_ids)
    removed_controls = sorted(before_ids - after_ids)

    shared = before_ids & after_ids
    for cid in sorted(shared):
        b = bm[cid]
        a = am[cid]
        bs = _status(b)
        as_ = _status(a)
        if bs == as_:
            continue
        title = _title(a) or _title(b)
        is_regression = _is_positive(bs) and _is_negative(as_)
        is_improvement = _is_negative(bs) and _is_positive(as_)
        if is_regression:
            regressions.append(
                ControlDelta(
                    control_id=cid,
                    title=title,
                    before_status=bs,
                    after_status=as_,
                    is_regression=True,
                )
            )
        elif is_improvement:
            improvements.append(
                ControlDelta(
                    control_id=cid,
                    title=title,
                    before_status=bs,
                    after_status=as_,
                    is_regression=False,
                )
            )

    expired: list[str] = []
    for cid in sorted(shared):
        b = bm[cid]
        a = am[cid]
        bw = b.get("waiver")
        aw = a.get("waiver")
        if isinstance(bw, dict) and (aw is None or not isinstance(aw, dict)):
            expired.append(cid)

    return DriftReport(
        before_path=before_path,
        after_path=after_path,
        before_kit_version=before_kv,
        after_kit_version=after_kv,
        regressions=regressions,
        improvements=improvements,
        new_controls=new_controls,
        removed_controls=removed_controls,
        expired_waivers=expired,
        has_regressions=bool(regressions),
        profile_mismatch=profile_mismatch,
        before_profile_id=before_pid,
        after_profile_id=after_pid,
    )


def load_report_json(path: Path) -> dict[str, Any]:
    """Load an evaluation report JSON object, annotating ``_path`` for diagnostics."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        msg = f"Report root must be an object: {path}"
        raise ValueError(msg)
    raw = dict(raw)
    raw["_path"] = str(path.resolve())
    return raw
