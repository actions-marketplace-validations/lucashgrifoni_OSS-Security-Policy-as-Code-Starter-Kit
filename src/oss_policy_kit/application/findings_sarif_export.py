"""SARIF 2.1.0 export of the correlated findings/1.0 artifact (ADR-030 A-S9).

The kit self-describes as an AGGREGATOR/CORRELATOR of named scanner tools —
never as the scanner that found the issues (scope-gate demand D8). Every
result carries per-result properties naming its source tool(s) and source
path(s); consumers uploading this to GitHub code scanning should beware of
double-reporting when a source tool already uploads its own SARIF.

Distinct from the per-control ``evaluate --sarif-output`` document
(``sarif_writer.py``), whose contract is pinned unchanged by regression tests.
"""

from __future__ import annotations

from typing import Any

_INFORMATION_URI = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit"

# Normalized severity -> SARIF result level.
_LEVEL_PAIRS: tuple[tuple[str, str], ...] = (
    ("critical", "error"),
    ("high", "error"),
    ("medium", "warning"),
    ("low", "note"),
    ("info", "note"),
    ("unknown", "none"),
)
_LEVEL: dict[str, str] = {k: v for k, v in _LEVEL_PAIRS}

_DOUBLE_REPORTING_NOTE = (
    "This run aggregates findings already produced by the source tools named in each "
    "result's properties. Uploading it alongside those tools' own SARIF uploads will "
    "double-report the same issues in code scanning."
)


def _result_for(finding: dict[str, Any]) -> dict[str, Any]:
    loc = finding["location"]
    result: dict[str, Any] = {
        "ruleId": finding["rule"] or finding["id"],
        "level": _LEVEL.get(finding["severity"]["normalized"], "none"),
        "message": {"text": finding["message"] or finding["rule"] or finding["id"]},
        "partialFingerprints": {"findingFingerprint/v1": finding["id"]},
        "properties": {
            # D8: mandatory per-result attribution to the ORIGINAL tool(s).
            "source_tools": sorted({s["tool"] for s in finding["sources"]}),
            "source_paths": sorted({s["source_path"] for s in finding["sources"]}),
            "normalized_severity": finding["severity"]["normalized"],
            "rank": finding["priority"]["rank"],
            "merged_from": finding["correlation"]["merged_from"],
            "waived": finding["waiver"]["waived"],
        },
    }
    if finding["vulnerability_ids"]:
        result["properties"]["vulnerability_ids"] = list(finding["vulnerability_ids"])
    if loc["file"]:
        physical: dict[str, Any] = {"artifactLocation": {"uri": loc["file"]}}
        if loc["line_start"]:
            region: dict[str, Any] = {"startLine": loc["line_start"]}
            if loc["line_end"]:
                region["endLine"] = loc["line_end"]
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    return result


def render_findings_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Project a findings/1.0 artifact dict into a SARIF 2.1.0 document."""

    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    all_tools: set[str] = set()
    for finding in report["findings"]:
        rid = finding["rule"] or finding["id"]
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid})
        all_tools.update(s["tool"] for s in finding["sources"])
        results.append(_result_for(finding))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oss-policy-kit correlate-findings",
                        "version": str(report.get("kit_version") or ""),
                        "informationUri": _INFORMATION_URI,
                        "shortDescription": {
                            "text": (
                                "Aggregator/correlator of scanner evidence - not a scanner. "
                                "Each result is attributed to its source tool(s) in "
                                "result.properties.source_tools."
                            )
                        },
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "role": "aggregator",
                    "source_tools": sorted(all_tools),
                    "findings_contract": report.get("contract_version"),
                    "double_reporting_note": _DOUBLE_REPORTING_NOTE,
                },
            }
        ],
    }
