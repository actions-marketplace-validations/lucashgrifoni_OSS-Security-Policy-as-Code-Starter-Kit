"""Normalize the external SARIF drops into the ADR-030 finding model (A-S3).

Reads the four user-dropped SARIF files under ``.oss-policy-kit/evidence/sast/``
(zizmor, poutine, osv-scanner, gitleaks) and projects each SARIF result into a
:class:`NormalizedFinding` — KEEPING per-result physicalLocation and message
(the control evaluators' generic adapter only tallies level counts and discards
them) plus the structured EPSS/KEV/CVSS enrichment properties the osv-scanner
SARIF may carry.

Reuses the hardened SARIF loader from the evaluators layer (size-capped via
``MAX_SARIF_BYTES``, nesting-depth-guarded, encoding-tolerant) instead of
growing another loader that could drift — the uncapped duplicate loaders were
a confirmed v9.0.x defect class.

Severity (x-severity-map/v1): the generic SARIF table maps result levels
``error/warning/note/none`` → ``high/medium/info/unknown`` with the SARIF-spec
fallback chain (result.level → rule defaultConfiguration.level → warning).
zizmor's richer ``properties.security_severity_level`` vocabulary maps
Critical..Informational → critical..info. ``PER_TOOL_SEVERITY_OVERRIDES`` is a
documented, deliberately EMPTY slot: the kit's own gate posture never rewrites
a source tool's severity (scope-gate demand D4) — gitleaks therefore maps via
the generic table (warning → medium).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oss_policy_kit.application.evaluators._shared import _load_sarif_runs, _sarif_rule_levels
from oss_policy_kit.application.input_limits import MAX_SARIF_BYTES, oversize_reason
from oss_policy_kit.domain.findings import (
    FindingLocation,
    FindingSource,
    NormalizedFinding,
    SeverityView,
    SourceRecord,
)

#: Registry of the four external SARIF sources: (filename, tool label).
#: Adding a source (e.g. a Trivy/Grype drop in v10.1) is a data-registration
#: change here plus, at most, a PER_TOOL_SEVERITY_OVERRIDES row — never a
#: schema change (binding design requirement from the v10 plan).
SARIF_SOURCES: tuple[tuple[str, str], ...] = (
    ("zizmor.sarif.json", "zizmor"),
    ("poutine.sarif.json", "poutine"),
    ("osv-scanner.sarif.json", "osv-scanner"),
    ("gitleaks.sarif.json", "gitleaks"),
)

_SARIF_DIR = Path(".oss-policy-kit") / "evidence" / "sast"

# Generic SARIF result-level table (x-severity-map/v1).
_SARIF_LEVEL_PAIRS: tuple[tuple[str, str], ...] = (
    ("error", "high"),
    ("warning", "medium"),
    ("note", "info"),
    ("none", "unknown"),
)
_SARIF_LEVEL: dict[str, str] = {k: v for k, v in _SARIF_LEVEL_PAIRS}

# zizmor's own vocabulary via result.properties.security_severity_level.
_ZIZMOR_SEVERITY_PAIRS: tuple[tuple[str, str], ...] = (
    ("CRITICAL", "critical"),
    ("HIGH", "high"),
    ("MEDIUM", "medium"),
    ("LOW", "low"),
    ("INFORMATIONAL", "info"),
    ("UNKNOWN", "unknown"),
)
_ZIZMOR_SEVERITY: dict[str, str] = {k: v for k, v in _ZIZMOR_SEVERITY_PAIRS}

#: Documented per-tool override slot — EMPTY by design in x-severity-map/v1.
#: The kit never rewrites a source tool's severity to match its own gate
#: posture (D4); a row here requires a map-version bump and a contract note.
PER_TOOL_SEVERITY_OVERRIDES: dict[str, dict[str, str]] = {}

_VULN_ID_PREFIXES = ("CVE-", "GHSA-", "PYSEC-", "OSV-", "RUSTSEC-", "GO-")


def normalize_sarif_level(level: str) -> str:
    """Map a SARIF result level to the normalized vocabulary (else ``unknown``)."""

    return _SARIF_LEVEL.get(level.strip().lower(), "unknown")


def _safe_float(raw: Any) -> float | None:
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _resolved_level(result: dict[str, Any], rule_levels: dict[str, str]) -> str:
    """SARIF-spec fallback chain: result.level -> rule default level -> warning."""

    level = result.get("level")
    if isinstance(level, str) and level.strip():
        return level.strip().lower()
    rid = result.get("ruleId")
    if isinstance(rid, str) and rid in rule_levels:
        return rule_levels[rid].strip().lower()
    return "warning"


def _location(result: dict[str, Any]) -> FindingLocation:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return FindingLocation()
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict):
        return FindingLocation()
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    raw_region = physical.get("region")
    region: dict[str, Any] = raw_region if isinstance(raw_region, dict) else {}
    start = region.get("startLine")
    end = region.get("endLine")
    return FindingLocation(
        file=str(uri) if isinstance(uri, str) and uri else None,
        line_start=start if isinstance(start, int) and start > 0 else None,
        line_end=end if isinstance(end, int) and end > 0 else None,
    )


def _vulnerability_ids(rule: str, props: dict[str, Any]) -> tuple[str, ...]:
    """Collect verbatim vulnerability ids (no alias resolution in findings/1.0)."""

    seen: list[str] = []
    for candidate in (rule, props.get("cve"), props.get("id")):
        if not isinstance(candidate, str):
            continue
        token = candidate.strip()
        if token.upper().startswith(_VULN_ID_PREFIXES) and token not in seen:
            seen.append(token)
    return tuple(seen)


def _normalize_result(
    tool: str, rel_path: str, result: dict[str, Any], rule_levels: dict[str, str]
) -> NormalizedFinding:
    rule = str(result.get("ruleId") or "")
    message_obj = result.get("message")
    message = str(message_obj.get("text") or "") if isinstance(message_obj, dict) else ""
    raw_props = result.get("properties")
    props: dict[str, Any] = raw_props if isinstance(raw_props, dict) else {}

    level = _resolved_level(result, rule_levels)
    zizmor_severity = props.get("security_severity_level")
    if tool == "zizmor" and isinstance(zizmor_severity, str) and zizmor_severity.strip():
        severity_original = zizmor_severity.strip()
        normalized = _ZIZMOR_SEVERITY.get(severity_original.upper(), normalize_sarif_level(level))
    else:
        severity_original = level
        normalized = normalize_sarif_level(level)

    kev_flag = props.get("kev")
    kev_str = kev_flag.strip().lower() if isinstance(kev_flag, str) else ""
    kev: bool | None = None
    if "kev" in props:
        kev = kev_flag in (True, 1) or kev_str in {"true", "yes", "1"}

    native_id = None
    for key in ("cve", "id"):
        value = props.get(key)
        if isinstance(value, str) and value.strip():
            native_id = value.strip()
            break

    return NormalizedFinding(
        id="",
        sources=(
            FindingSource(
                tool=tool,
                source_path=rel_path,
                rule=rule,
                severity_original=severity_original,
                message=message,
                native_id=native_id,
            ),
        ),
        rule=rule,
        message=message,
        severity=SeverityView(normalized=normalized, by_source=((tool, severity_original),)),
        location=_location(result),
        vulnerability_ids=_vulnerability_ids(rule, props),
        epss=_safe_float(props.get("epss_score", props.get("epss"))),
        kev=kev,
        cvss=_safe_float(props.get("cvss_score", props.get("security-severity"))),
    )


def normalize_sarif_sources(repo_root: Path) -> tuple[list[NormalizedFinding], list[SourceRecord]]:
    """Project the four external SARIF drops under *repo_root* into findings.

    Deterministic (registry order, in-document result order). Missing, oversize,
    and unreadable files contribute an honest :class:`SourceRecord` and no
    findings — never a failure.
    """

    findings: list[NormalizedFinding] = []
    records: list[SourceRecord] = []
    for filename, tool in SARIF_SOURCES:
        rel = (_SARIF_DIR / filename).as_posix()
        path = repo_root / _SARIF_DIR / filename
        if not path.is_file():
            records.append(SourceRecord(path=rel, kind="external-sarif", tool=tool, status="missing"))
            continue
        if oversize_reason(path, MAX_SARIF_BYTES, label=filename) is not None:
            records.append(SourceRecord(path=rel, kind="external-sarif", tool=tool, status="oversize"))
            continue
        runs, err = _load_sarif_runs(path)
        if err is not None or runs is None:
            records.append(SourceRecord(path=rel, kind="external-sarif", tool=tool, status="unreadable"))
            continue
        tool_version: str | None = None
        for run in runs:
            if not isinstance(run, dict):
                continue
            driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run.get("tool"), dict) else {}
            if tool_version is None:
                version = driver.get("semanticVersion") or driver.get("version")
                if isinstance(version, str) and version.strip():
                    tool_version = version.strip()
            rule_levels = _sarif_rule_levels(run)
            results = run.get("results")
            if not isinstance(results, list):
                continue
            for result in results:
                if isinstance(result, dict):
                    findings.append(_normalize_result(tool, rel, result, rule_levels))
        records.append(SourceRecord(path=rel, kind="external-sarif", tool=tool, status="ok", tool_version=tool_version))
    return findings, records


__all__ = [
    "PER_TOOL_SEVERITY_OVERRIDES",
    "SARIF_SOURCES",
    "normalize_sarif_level",
    "normalize_sarif_sources",
]
