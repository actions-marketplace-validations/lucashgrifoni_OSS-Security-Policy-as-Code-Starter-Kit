"""Assemble the findings/1.0 artifact dict (ADR-030 A-S5).

Orchestrates the read-only pipeline — kit-evidence normalizers (A-S2) +
external-SARIF normalizers (A-S3) -> correlation engine (A-S4) -> the
``oss-policy-kit/findings/1.0`` artifact. Paths are privacy-sanitized by
default (basename-only ``target_path``, like reports/2.0), reusing the
reporting-layer sanitizer so the two artifacts behave identically.

Pure and single-run: reads only under ``repo_root`` + the fixed evidence
paths, no network, no persistence, no cross-run state.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oss_policy_kit.application.clock import report_generated_at
from oss_policy_kit.application.finding_correlation import correlate
from oss_policy_kit.application.finding_normalization import (
    NORMALIZED_SEVERITIES,
    normalize_kit_evidence,
)
from oss_policy_kit.application.finding_sarif import normalize_sarif_sources
from oss_policy_kit.application.reporting import _sanitize_target_path_for_payload
from oss_policy_kit.domain.findings import NormalizedFinding, SourceRecord

FINDINGS_SCHEMA_VERSION = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/findings/1.0"
FINDINGS_CONTRACT_VERSION = "findings/1.0"


def _source_record_to_dict(record: SourceRecord) -> dict[str, Any]:
    return {
        "path": record.path,
        "kind": record.kind,
        "tool": record.tool,
        "tool_version": record.tool_version,
        "schema_version": record.schema_version,
        "status": record.status,
    }


def _finding_to_dict(finding: NormalizedFinding) -> dict[str, Any]:
    loc = finding.location
    lg = loc.logical
    return {
        "id": finding.id,
        "sources": [
            {
                "tool": s.tool,
                "source_path": s.source_path,
                "rule": s.rule,
                "severity_original": s.severity_original,
                "message": s.message,
                "native_id": s.native_id,
            }
            for s in finding.sources
        ],
        "rule": finding.rule,
        "message": finding.message,
        "cwe": list(finding.cwe),
        "owasp": list(finding.owasp),
        "severity": {
            "normalized": finding.severity.normalized,
            "by_source": [{"tool": t, "original": o} for t, o in finding.severity.by_source],
        },
        "location": {
            "file": loc.file,
            "line_start": loc.line_start,
            "line_end": loc.line_end,
            "logical": {
                "type": lg.type,
                "resource_type": lg.resource_type,
                "resource_name": lg.resource_name,
                "kind": lg.kind,
                "namespace": lg.namespace,
                "name": lg.name,
            },
        },
        "component": finding.component,
        "vulnerability_ids": list(finding.vulnerability_ids),
        "epss": finding.epss,
        "kev": finding.kev,
        "cvss": finding.cvss,
        "reachability": finding.reachability,
        "waiver": {
            "waived": finding.waiver.waived,
            "matched_by": finding.waiver.matched_by,
            "waiver_owner": finding.waiver.waiver_owner,
            "expires_at": finding.waiver.expires_at,
        },
        "priority": {
            "rank": finding.priority.rank if finding.priority else 0,
            "rationale": finding.priority.rationale if finding.priority else "",
        },
        "correlation": {
            "key": finding.correlation.key if finding.correlation else "",
            "merged_from": finding.correlation.merged_from if finding.correlation else 1,
            "confidence": finding.correlation.confidence if finding.correlation else "exact",
        },
    }


def collect_normalized_findings(
    repo_root: Path,
) -> tuple[list[NormalizedFinding], list[SourceRecord]]:
    """Read + normalize all kit-evidence and external-SARIF sources under *repo_root*."""

    kit_findings, kit_records = normalize_kit_evidence(repo_root)
    sarif_findings, sarif_records = normalize_sarif_sources(repo_root)
    return kit_findings + sarif_findings, kit_records + sarif_records


def build_findings_report(
    repo_root: Path,
    *,
    kit_version: str,
    include_absolute_path: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build the complete findings/1.0 artifact dict for *repo_root*.

    Deterministic given the same inputs (``generated_at`` defaults to the
    SOURCE_DATE_EPOCH-honoring report clock). Missing/unreadable sources are
    recorded in ``sources_read`` and never raise.
    """

    findings, records = collect_normalized_findings(repo_root)
    result = correlate(findings)

    by_severity = dict.fromkeys(NORMALIZED_SEVERITIES, 0)
    for f in result.findings:
        by_severity[f.severity.normalized] = by_severity.get(f.severity.normalized, 0) + 1

    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "contract_version": FINDINGS_CONTRACT_VERSION,
        "generated_at": generated_at if generated_at is not None else report_generated_at(),
        "kit_version": kit_version,
        "target_path": _sanitize_target_path_for_payload(str(repo_root), include_absolute=include_absolute_path),
        "sources_read": [_source_record_to_dict(r) for r in records],
        "findings_total": len(result.findings),
        "findings_by_severity": by_severity,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "correlation": result.to_dict(),
        "extensions": {},
    }
