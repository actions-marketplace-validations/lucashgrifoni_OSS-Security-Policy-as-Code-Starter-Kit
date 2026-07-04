"""Correlate normalized findings into one deduplicated, ranked set (ADR-030 A-S4).

Pure, deterministic, single-run (anti-ASPM fence: no state, no persistence, no
network). Given the ``NormalizedFinding`` list from the kit-evidence and
external-SARIF normalizers, this module:

1. Builds a deterministic **opk-fk/v1** correlation key per finding, scoped to
   one of four axes (vuln / code / iac / k8s). The full pre-hash canonical
   string is retained for audit; ``sha256`` → first 16 hex characters form the
   finding id ``opk-fk/v1:<hex>``.
2. **Conservatively** collapses findings that share the same key (under-merge:
   we would rather keep two distinct issues separate than merge two different
   ones). Cross-axis findings never merge; a null/partial location is a
   distinct sentinel that never merges with a complete one; the same key with a
   different message stays separate via a message-digest suffix.
3. Assigns a **total-order deterministic rank**: KEV first, then EPSS desc
   (nulls last), then normalized-severity desc, then file asc, rule asc, id asc.

Correlation records EPSS/KEV/CVSS carried by the sources; it never fetches,
re-scores, or invents them, and it never changes any control state.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import Any

from oss_policy_kit.domain.findings import (
    CorrelationInfo,
    FindingPriority,
    FindingSource,
    NormalizedFinding,
    SeverityView,
)

#: Version of the correlation key spec. Bump only additively; opk-fk/v2 may add
#: user-supplied alias tables without changing any /v1 id.
KEY_SPEC = "opk-fk/v1"

CORRELATION_STRATEGY = "conservative-under-merge"

# Rank weight for the normalized severity vocabulary (higher = more urgent).
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def _canonical_key(finding: NormalizedFinding) -> str:
    """Build the axis-scoped ``opk-fk/v1`` canonical string (retained verbatim).

    Axes (first match wins):
    - **vuln**: any verbatim vulnerability id present -> keyed on the ids +
      component. Cross-tool merges happen here (same CVE from two scanners).
    - **k8s** / **iac**: logical resource coordinates.
    - **code**: file + line for a rule-based code finding.
    Findings that share none of these fall back to a message-digest axis so
    two genuinely different issues never collapse.
    """

    loc = finding.location
    logical = loc.logical
    parts: list[str]
    if finding.vulnerability_ids:
        vids = "+".join(sorted(finding.vulnerability_ids))
        parts = ["vuln", f"vid={vids}", f"component={finding.component or '-'}"]
    elif logical.type == "k8s-object":
        parts = [
            "k8s",
            f"rule={finding.rule}",
            f"file={loc.file or '-'}",
            f"kind={logical.kind or '-'}",
            f"ns={logical.namespace or '-'}",
            f"name={logical.name or '-'}",
        ]
    elif logical.type == "resource":
        parts = [
            "iac",
            f"rule={finding.rule}",
            f"file={loc.file or '-'}",
            f"rtype={logical.resource_type or '-'}",
            f"rname={logical.resource_name or '-'}",
        ]
    elif loc.file is not None:
        # code axis: null line is a distinct sentinel (never merges with a line)
        line = str(loc.line_start) if loc.line_start is not None else "-"
        parts = ["code", f"rule={finding.rule}", f"file={loc.file}", f"line={line}"]
    else:
        # No usable coordinates: separate by rule + message digest so distinct
        # messages stay distinct (conservative under-merge).
        digest = hashlib.sha256(finding.message.encode("utf-8")).hexdigest()[:12]
        parts = ["misc", f"rule={finding.rule}", f"msgdigest={digest}"]

    # Message-digest suffix on the mergeable axes too: same key + different
    # message => keep separate (under-merge). Vuln axis omits it so the same
    # CVE from two tools with different wording still correlates.
    if parts[0] != "vuln":
        digest = hashlib.sha256(finding.message.encode("utf-8")).hexdigest()[:12]
        parts.append(f"msgdigest={digest}")

    return KEY_SPEC + "|" + "|".join(parts)


def _finding_id(canonical_key: str) -> str:
    return f"{KEY_SPEC}:" + hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16]


def _group_member_sort_key(f: NormalizedFinding) -> tuple[Any, ...]:
    """A TOTAL order over a group's members, independent of input order.

    Every field that can differ between two findings sharing a canonical key
    (e.g. two reports of the same CVE with different EPSS or location) is folded
    in, so ``sorted`` breaks all ties deterministically — the merged
    ``sources``/``by_source``/representative-location resolution is then
    reproducible no matter what order findings arrived in. Genuinely identical
    findings tie, which is harmless (their merge contribution is identical).
    """

    loc = f.location
    lg = loc.logical
    return (
        tuple((s.tool, s.source_path, s.rule, s.severity_original, s.message, s.native_id or "") for s in f.sources),
        f.rule,
        f.message,
        f.severity.normalized,
        loc.file or "",
        loc.line_start if loc.line_start is not None else -1,
        loc.line_end if loc.line_end is not None else -1,
        lg.type or "",
        lg.resource_type or "",
        lg.resource_name or "",
        lg.kind or "",
        lg.namespace or "",
        lg.name or "",
        tuple(sorted(f.vulnerability_ids)),
        tuple(sorted(f.cwe)),
        tuple(sorted(f.owasp)),
        f.component or "",
        f.epss if f.epss is not None else -1.0,
        1 if f.kev else 0,
        f.cvss if f.cvss is not None else -1.0,
    )


def _merge_group(canonical_key: str, group: list[NormalizedFinding]) -> NormalizedFinding:
    """Collapse findings sharing a key into one correlated finding.

    Deterministic field resolution: sources concatenated in input order (which
    is registry+in-file order upstream); rule is the lexicographically-first;
    severity is the strongest normalized value across the group with every
    source's original preserved; enrichment takes the strongest present value
    (kev OR; epss/cvss max); cwe/owasp/vuln-ids unioned and sorted.
    """

    sources: list[FindingSource] = []
    for f in group:
        sources.extend(f.sources)

    rule = min(f.rule for f in group)
    representative = min(group, key=lambda f: (f.rule, f.message))
    message = representative.message
    location = representative.location

    normalized = max((f.severity.normalized for f in group), key=lambda s: _SEVERITY_RANK.get(s, 0))
    by_source: tuple[tuple[str, str], ...] = tuple(pair for f in group for pair in f.severity.by_source)

    cwe = tuple(sorted({c for f in group for c in f.cwe}))
    owasp = tuple(sorted({o for f in group for o in f.owasp}))
    vuln_ids = tuple(sorted({v for f in group for v in f.vulnerability_ids}))

    kev_values = [f.kev for f in group if f.kev is not None]
    kev = any(kev_values) if kev_values else None
    epss_values = [f.epss for f in group if f.epss is not None]
    epss = max(epss_values) if epss_values else None
    cvss_values = [f.cvss for f in group if f.cvss is not None]
    cvss = max(cvss_values) if cvss_values else None
    component = next((f.component for f in group if f.component), None)

    return NormalizedFinding(
        id=_finding_id(canonical_key),
        sources=tuple(sources),
        rule=rule,
        message=message,
        severity=SeverityView(normalized=normalized, by_source=by_source),
        location=location,
        cwe=cwe,
        owasp=owasp,
        component=component,
        vulnerability_ids=vuln_ids,
        epss=epss,
        kev=kev,
        cvss=cvss,
        reachability=None,
        correlation=CorrelationInfo(key=canonical_key, merged_from=len(group), confidence="exact"),
    )


def _effective_signals(
    finding: NormalizedFinding, enrichment: dict[str, dict[str, Any]] | None
) -> tuple[bool, float | None, bool]:
    """Return ``(kev_effective, epss_effective, snapshot_contributed)`` for ranking.

    An offline user-supplied enrichment snapshot may fill KEV/EPSS gaps for
    RANKING ONLY (ADR-030 Amendment / D6): the finding's own ``kev``/``epss``
    fields, its severity, and every control state stay untouched. Source-reported
    values always win over the snapshot.
    """

    kev_eff = bool(finding.kev)
    epss_eff = finding.epss
    contributed = False
    if enrichment:
        for vid in finding.vulnerability_ids:
            entry = enrichment.get(vid)
            if not isinstance(entry, dict):
                continue
            if finding.kev is None and not kev_eff:
                raw_kev = entry.get("kev")
                kev_str = raw_kev.strip().lower() if isinstance(raw_kev, str) else ""
                if raw_kev in (True, 1) or kev_str in {"true", "yes", "1"}:
                    kev_eff = True
                    contributed = True
            if epss_eff is None:
                try:
                    raw_epss = float(entry["epss"]) if entry.get("epss") is not None else None
                except (TypeError, ValueError):
                    raw_epss = None
                # EPSS is a probability in [0.0, 1.0]; ignore out-of-range snapshot
                # values (e.g. 999 or -1) so a garbage number cannot warp ranking.
                if raw_epss is not None and 0.0 <= raw_epss <= 1.0:
                    epss_eff = raw_epss
                    contributed = True
    return kev_eff, epss_eff, contributed


def _rank_sort_key(
    finding: NormalizedFinding, enrichment: dict[str, dict[str, Any]] | None = None
) -> tuple[int, float, int, str, str, str]:
    """Total order: KEV first, EPSS desc (nulls last), severity desc, then stable tie-breaks."""

    kev_eff, epss_eff, _ = _effective_signals(finding, enrichment)
    kev_rank = 0 if kev_eff else 1  # True -> 0 (first)
    epss_rank = -(epss_eff if epss_eff is not None else -1.0)  # higher epss first; null last
    sev_rank = -_SEVERITY_RANK.get(finding.severity.normalized, 0)  # higher severity first
    file_key = finding.location.file or "￿"  # None sorts last
    return (kev_rank, epss_rank, sev_rank, file_key, finding.rule, finding.id)


@dataclass(slots=True, frozen=True)
class CorrelationResult:
    """The correlated finding set plus deterministic correlation stats."""

    findings: tuple[NormalizedFinding, ...]
    merged_groups: int  # groups that collapsed >1 source-finding
    cross_tool_merges: int  # merged groups whose sources span >1 distinct tool

    def to_dict(self) -> dict[str, object]:
        return {
            "strategy": CORRELATION_STRATEGY,
            "key_spec": KEY_SPEC,
            "merged_groups": self.merged_groups,
            "cross_tool_merges": self.cross_tool_merges,
        }


def correlate(
    findings: list[NormalizedFinding], enrichment: dict[str, dict[str, Any]] | None = None
) -> CorrelationResult:
    """Correlate + rank *findings* deterministically (idempotent, order-independent)."""

    # Group by canonical key. Sort keys so output is independent of input order.
    groups: dict[str, list[NormalizedFinding]] = {}
    for f in findings:
        groups.setdefault(_canonical_key(f), []).append(f)

    merged: list[NormalizedFinding] = []
    merged_groups = 0
    cross_tool_merges = 0
    for key in sorted(groups):
        # Sort each group deterministically so the merged sources/by_source
        # concatenation is independent of the order findings arrived in.
        group = sorted(groups[key], key=_group_member_sort_key)
        finding = _merge_group(key, group)
        merged.append(finding)
        if len(group) > 1:
            merged_groups += 1
            if len({s.tool for f in group for s in f.sources}) > 1:
                cross_tool_merges += 1

    merged.sort(key=lambda f: _rank_sort_key(f, enrichment))
    ranked = tuple(
        replace(f, priority=FindingPriority(rank=i + 1, rationale=_rationale(f, enrichment)))
        for i, f in enumerate(merged)
    )
    return CorrelationResult(findings=ranked, merged_groups=merged_groups, cross_tool_merges=cross_tool_merges)


def _rationale(finding: NormalizedFinding, enrichment: dict[str, dict[str, Any]] | None = None) -> str:
    bits: list[str] = []
    kev_eff, epss_eff, contributed = _effective_signals(finding, enrichment)
    snapshot_tag = " (snapshot)" if contributed else ""
    if kev_eff:
        bits.append("KEV-listed" + ("" if finding.kev else snapshot_tag))
    if epss_eff is not None:
        bits.append(f"EPSS={epss_eff:.2f}" + ("" if finding.epss is not None else snapshot_tag))
    bits.append(f"severity={finding.severity.normalized}")
    if finding.correlation and finding.correlation.merged_from > 1:
        bits.append(f"merged×{finding.correlation.merged_from}")
    return "; ".join(bits)


__all__ = [
    "CORRELATION_STRATEGY",
    "KEY_SPEC",
    "CorrelationResult",
    "correlate",
]
