"""A-S3 (ADR-030): external-SARIF normalization into the finding model.

Covers the four-source registry, the SARIF level fallback chain, zizmor's
security_severity_level vocabulary, gitleaks via the generic table (D4),
EPSS/KEV/CVSS enrichment extraction, physicalLocation retention, and honest
SourceRecord statuses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import finding_sarif as fs

_SAST = Path(".oss-policy-kit") / "evidence" / "sast"


def _sarif(
    results: list[dict[str, Any]], *, rules: list[dict[str, Any]] | None = None, version: str = "1.0.0"
) -> dict[str, Any]:
    driver: dict[str, Any] = {"name": "tool", "version": version}
    if rules is not None:
        driver["rules"] = rules
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def _write(repo: Path, filename: str, doc: dict[str, Any]) -> Path:
    d = repo / _SAST
    d.mkdir(parents=True, exist_ok=True)
    p = d / filename
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _result(
    rule: str,
    *,
    level: str | None = None,
    text: str = "msg",
    uri: str | None = "wf.yml",
    start: int | None = 4,
    end: int | None = 6,
    props: dict[str, Any] | None = None,
) -> dict[str, Any]:
    r: dict[str, Any] = {"ruleId": rule, "message": {"text": text}}
    if level is not None:
        r["level"] = level
    if uri is not None:
        region: dict[str, Any] = {}
        if start is not None:
            region["startLine"] = start
        if end is not None:
            region["endLine"] = end
        r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}]
    if props is not None:
        r["properties"] = props
    return r


def test_zizmor_uses_security_severity_level(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "zizmor.sarif.json",
        _sarif([_result("template-injection", level="warning", props={"security_severity_level": "Critical"})]),
    )
    findings, records = fs.normalize_sarif_sources(tmp_path)
    f = findings[0]
    assert f.severity.normalized == "critical"
    assert f.severity.by_source == (("zizmor", "Critical"),)
    assert next(r for r in records if r.tool == "zizmor").status == "ok"


def test_level_fallback_chain_result_rule_default_warning(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "poutine.sarif.json",
        _sarif(
            [
                _result("R1", level="error"),  # explicit level -> high
                _result("R2"),  # no level, rule default note -> info
                _result("R3"),  # no level, no rule default -> warning -> medium
            ],
            rules=[{"id": "R2", "defaultConfiguration": {"level": "note"}}],
        ),
    )
    findings, _ = fs.normalize_sarif_sources(tmp_path)
    by_rule = {f.rule: f.severity.normalized for f in findings}
    assert by_rule == {"R1": "high", "R2": "info", "R3": "medium"}


def test_gitleaks_maps_via_generic_table(tmp_path: Path) -> None:
    # D4: the kit's gate posture never rewrites a source severity — gitleaks
    # warning stays medium via the generic table, and the override slot is empty.
    _write(tmp_path, "gitleaks.sarif.json", _sarif([_result("generic-api-key", level="warning")]))
    findings, _ = fs.normalize_sarif_sources(tmp_path)
    assert findings[0].severity.normalized == "medium"
    assert fs.PER_TOOL_SEVERITY_OVERRIDES == {}


def test_osv_enrichment_and_vulnerability_ids(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "osv-scanner.sarif.json",
        _sarif(
            [
                _result(
                    "CVE-2026-1234",
                    level="error",
                    props={"kev": "true", "epss_score": "0.91", "cvss_score": 9.8, "cve": "CVE-2026-1234"},
                ),
                _result("GHSA-xxxx-yyyy", level="warning", props={"epss": 0.02}),
            ]
        ),
    )
    findings, _ = fs.normalize_sarif_sources(tmp_path)
    first, second = findings
    assert first.kev is True and first.epss == 0.91 and first.cvss == 9.8
    assert first.vulnerability_ids == ("CVE-2026-1234",)
    assert first.sources[0].native_id == "CVE-2026-1234"
    assert second.kev is None  # no kev property -> unknown, not False
    assert second.epss == 0.02 and second.cvss is None
    assert second.vulnerability_ids == ("GHSA-xxxx-yyyy",)


def test_physical_location_kept_and_missing_region_tolerated(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "zizmor.sarif.json",
        _sarif(
            [
                _result("R1", level="note", uri=".github/workflows/ci.yml", start=12, end=14),
                _result("R2", level="note", uri="other.yml", start=None, end=None),
                _result("R3", level="note", uri=None),
            ]
        ),
    )
    findings, _ = fs.normalize_sarif_sources(tmp_path)
    by_rule = {f.rule: f.location for f in findings}
    assert by_rule["R1"].file == ".github/workflows/ci.yml"
    assert (by_rule["R1"].line_start, by_rule["R1"].line_end) == (12, 14)
    assert by_rule["R2"].file == "other.yml" and by_rule["R2"].line_start is None
    assert by_rule["R3"].file is None


def test_missing_and_unreadable_are_honest(tmp_path: Path) -> None:
    d = tmp_path / _SAST
    d.mkdir(parents=True)
    (d / "poutine.sarif.json").write_text('{"runs": []}', encoding="utf-16")  # not UTF-8 -> unreadable
    findings, records = fs.normalize_sarif_sources(tmp_path)
    assert findings == []
    by_tool = {r.tool: r.status for r in records}
    assert by_tool["poutine"] == "unreadable"
    assert by_tool["zizmor"] == "missing"
    assert by_tool["gitleaks"] == "missing"
    assert by_tool["osv-scanner"] == "missing"
    assert {r.kind for r in records} == {"external-sarif"}


def test_oversize_sarif_is_recorded_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path, "gitleaks.sarif.json", _sarif([_result("R1", level="error")]))
    monkeypatch.setattr(fs, "MAX_SARIF_BYTES", 4)
    findings, records = fs.normalize_sarif_sources(tmp_path)
    assert findings == []
    assert next(r for r in records if r.tool == "gitleaks").status == "oversize"


def test_tool_version_recorded_and_deterministic(tmp_path: Path) -> None:
    _write(tmp_path, "zizmor.sarif.json", _sarif([_result("R1", level="note")], version="1.5.2"))
    first = fs.normalize_sarif_sources(tmp_path)
    second = fs.normalize_sarif_sources(tmp_path)
    assert first == second
    assert next(r for r in first[1] if r.tool == "zizmor").tool_version == "1.5.2"
