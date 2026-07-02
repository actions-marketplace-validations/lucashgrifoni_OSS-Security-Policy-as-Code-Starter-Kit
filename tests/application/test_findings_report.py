"""A-S5 (ADR-030): the findings/1.0 artifact assembler + packaged schema.

Validates the assembled artifact against its own packaged schema, checks the
empty-repo (all-sources-missing) shape, the end-to-end pipeline over real
evidence + SARIF, path privacy-by-default, determinism, and that the public
mirror matches the packaged schema byte-for-byte.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from tests.conftest import ROOT

from oss_policy_kit.application import findings_report as fr

_PACKAGED_SCHEMA = ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "findings" / "1.0.json"
_PUBLIC_MIRROR = ROOT / "reports" / "schema" / "findings-1.0.schema.json"
_EVID = Path(".oss-policy-kit") / "evidence"


def _schema() -> dict:
    return json.loads(_PACKAGED_SCHEMA.read_text(encoding="utf-8"))


def _write_evidence(repo: Path, rel: str | Path, payload: object) -> None:
    p = repo / _EVID / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload), encoding="utf-8")


def _semgrep_envelope(findings: list[dict]) -> dict:
    return {
        "schema_version": "oss-policy-kit/evidence/sast-semgrep/v1",
        "tool": "semgrep",
        "tool_version": "1.100.0",
        "status": "ok",
        "target": "x",
        "scanned_at": "2026-06-10T00:00:00Z",
        "attested_at": "2026-06-10T00:00:00Z",
        "attested_by": "test",
        "findings_total": len(findings),
        "findings": findings,
    }


def _osv_sarif(results: list[dict]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "osv-scanner", "version": "2.0.0"}}, "results": results}],
    }


def test_empty_repo_yields_valid_artifact_with_honest_sources(tmp_path: Path) -> None:
    report = fr.build_findings_report(tmp_path, kit_version="9.0.3", generated_at="2026-06-15T12:00:00Z")
    Draft202012Validator(_schema()).validate(report)
    assert report["contract_version"] == "findings/1.0"
    assert report["findings_total"] == 0
    assert report["findings"] == []
    assert report["findings_by_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    # 6 kit-evidence + 4 external-sarif sources all honestly recorded as missing.
    statuses = {r["path"]: r["status"] for r in report["sources_read"]}
    assert len(statuses) == 10
    assert set(statuses.values()) == {"missing"}


def test_end_to_end_pipeline_validates_and_ranks(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "sast-semgrep.json",
        _semgrep_envelope(
            [
                {
                    "rule_id": "python.eval",
                    "severity": "ERROR",
                    "message": "eval",
                    "file": "app.py",
                    "line_start": 3,
                    "line_end": 3,
                    "cwe": ["CWE-95"],
                    "owasp": ["A03:2021"],
                }
            ]
        ),
    )
    _write_evidence(
        tmp_path,
        Path("sast") / "osv-scanner.sarif.json",
        _osv_sarif(
            [
                {
                    "ruleId": "CVE-2026-1",
                    "level": "error",
                    "message": {"text": "vulnerable dep"},
                    "properties": {"kev": "true", "epss_score": 0.9, "cvss_score": 9.8, "cve": "CVE-2026-1"},
                }
            ]
        ),
    )
    report = fr.build_findings_report(tmp_path, kit_version="9.0.3", generated_at="2026-06-15T12:00:00Z")
    Draft202012Validator(_schema()).validate(report)
    assert report["findings_total"] == 2
    # KEV-listed dependency ranks first.
    assert report["findings"][0]["vulnerability_ids"] == ["CVE-2026-1"]
    assert report["findings"][0]["kev"] is True
    assert report["findings"][0]["priority"]["rank"] == 1
    assert report["findings"][0]["id"].startswith("opk-fk/v1:")
    # the semgrep code finding carries its CWE and normalized severity
    code = next(f for f in report["findings"] if f["rule"] == "python.eval")
    assert code["cwe"] == ["CWE-95"]
    assert code["severity"]["normalized"] == "high"
    assert code["reachability"] is None
    # both sources recorded ok
    ok = {r["tool"]: r["status"] for r in report["sources_read"] if r["status"] == "ok"}
    assert ok.get("semgrep") == "ok" and ok.get("osv-scanner") == "ok"


def test_target_path_is_basename_by_default(tmp_path: Path) -> None:
    repo = tmp_path / "secret-repo-name"
    repo.mkdir()
    default = fr.build_findings_report(repo, kit_version="9.0.3", generated_at="t")
    assert default["target_path"] == "secret-repo-name"
    absolute = fr.build_findings_report(repo, kit_version="9.0.3", generated_at="t", include_absolute_path=True)
    assert absolute["target_path"] == str(repo)


def test_artifact_is_deterministic(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "iac-terraform.json",
        {
            "schema_version": "oss-policy-kit/evidence/iac-terraform/v1",
            "tool": "oss-policy-kit-iac-parser",
            "status": "ok",
            "target": "x",
            "scanned_at": "t",
            "attested_at": "t",
            "attested_by": "t",
            "findings_total": 2,
            "findings": [
                {
                    "rule_id": "IAC-TF-002",
                    "severity": "LOW",
                    "message": "b",
                    "file": "b.tf",
                    "resource_type": "t",
                    "resource_name": "y",
                },
                {
                    "rule_id": "IAC-TF-001",
                    "severity": "HIGH",
                    "message": "a",
                    "file": "a.tf",
                    "resource_type": "t",
                    "resource_name": "x",
                },
            ],
        },
    )
    a = fr.build_findings_report(tmp_path, kit_version="9.0.3", generated_at="t")
    b = fr.build_findings_report(tmp_path, kit_version="9.0.3", generated_at="t")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_public_mirror_matches_packaged_schema() -> None:
    assert _PUBLIC_MIRROR.is_file(), "public findings/1.0 schema mirror is missing"
    packaged = json.loads(_PACKAGED_SCHEMA.read_text(encoding="utf-8"))
    mirror = json.loads(_PUBLIC_MIRROR.read_text(encoding="utf-8"))
    assert packaged == mirror


def test_generated_at_honors_source_date_epoch(tmp_path: Path) -> None:
    # No explicit generated_at -> uses the SOURCE_DATE_EPOCH-frozen clock (conftest pins it).
    report = fr.build_findings_report(tmp_path, kit_version="9.0.3")
    assert report["generated_at"].startswith("2026-06-15T12:00:00")
