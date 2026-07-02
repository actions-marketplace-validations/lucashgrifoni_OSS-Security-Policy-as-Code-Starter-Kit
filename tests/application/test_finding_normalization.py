"""A-S2 (ADR-030): kit-evidence normalization into the finding model.

Covers the six-source registry, the x-severity-map/v1 vocabulary, honest
SourceRecord statuses (missing / oversize / unreadable / scanner-reported),
and the Pulumi line_start fix flowing end-to-end into the evidence payload.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from tests.conftest import ROOT

from oss_policy_kit.application import finding_normalization as fn
from oss_policy_kit.infrastructure.iac.pulumi import scanner as pulumi
from oss_policy_kit.infrastructure.scanners import semgrep_adapter

_EVID = Path(".oss-policy-kit") / "evidence"


def _write_evidence(repo: Path, filename: str, payload: object) -> Path:
    d = repo / _EVID
    d.mkdir(parents=True, exist_ok=True)
    p = d / filename
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _envelope(tool: str, findings: list[dict], status: str = "ok") -> dict:
    return {
        "schema_version": f"oss-policy-kit/evidence/{tool}/v1",
        "tool": tool,
        "tool_version": "1.2.3",
        "status": status,
        "target": "example",
        "scanned_at": "2026-06-10T00:00:00Z",
        "attested_at": "2026-06-10T00:00:00Z",
        "attested_by": "test",
        "findings_total": len(findings),
        "findings": findings,
    }


# --------------------------------------------------------------------------- #
# per-family normalization
# --------------------------------------------------------------------------- #


def test_semgrep_finding_normalizes_fields_and_severity(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "sast-semgrep.json",
        _envelope(
            "semgrep",
            [
                {
                    "rule_id": "python.lang.security.dangerous-eval",
                    "severity": "ERROR",
                    "message": "eval() on user input",
                    "file": "app/main.py",
                    "line_start": 10,
                    "line_end": 12,
                    "cwe": ["CWE-95"],
                    "owasp": ["A03:2021"],
                }
            ],
        ),
    )
    findings, records = fn.normalize_kit_evidence(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "python.lang.security.dangerous-eval"
    assert f.severity.normalized == "high"  # ERROR -> high (x-severity-map/v1)
    assert f.severity.by_source == (("semgrep", "ERROR"),)
    assert f.location.file == "app/main.py"
    assert (f.location.line_start, f.location.line_end) == (10, 12)
    assert f.cwe == ("CWE-95",) and f.owasp == ("A03:2021",)
    assert f.sources[0].source_path == ".oss-policy-kit/evidence/sast-semgrep.json"
    assert f.id == ""  # correlation assigns opk-fk ids later
    semgrep_record = next(r for r in records if r.path.endswith("sast-semgrep.json"))
    assert semgrep_record.status == "ok" and semgrep_record.tool == "semgrep"


def test_iac_finding_normalizes_resource_location(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "iac-terraform.json",
        _envelope(
            "oss-policy-kit-iac-parser",
            [
                {
                    "rule_id": "IAC-TF-001",
                    "severity": "CRITICAL",
                    "message": "public bucket",
                    "file": "main.tf",
                    "resource_type": "aws_s3_bucket",
                    "resource_name": "logs",
                }
            ],
        ),
    )
    findings, _ = fn.normalize_kit_evidence(tmp_path)
    f = findings[0]
    assert f.severity.normalized == "critical"
    assert f.location.logical.type == "resource"
    assert f.location.logical.resource_type == "aws_s3_bucket"
    assert f.location.logical.resource_name == "logs"


def test_pulumi_line_start_flows_into_the_model(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "iac-pulumi.json",
        _envelope(
            "oss-policy-kit-pulumi-parser",
            [
                {
                    "rule_id": "IAC-PUL-001",
                    "severity": "HIGH",
                    "message": "public acl",
                    "file": "infra.py",
                    "resource_type": "aws.s3.Bucket",
                    "resource_name": "b",
                    "line_start": 7,
                }
            ],
        ),
    )
    findings, _ = fn.normalize_kit_evidence(tmp_path)
    assert findings[0].location.line_start == 7


def test_k8s_finding_normalizes_object_location_and_unknown_severity(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "k8s-baseline.json",
        _envelope(
            "oss-policy-kit-k8s-parser",
            [
                {
                    "rule_id": "K8S-001",
                    "severity": "weird",
                    "message": "privileged pod",
                    "file": "deploy.yaml",
                    "kind": "Deployment",
                    "namespace": "prod",
                    "name": "api",
                }
            ],
        ),
    )
    findings, _ = fn.normalize_kit_evidence(tmp_path)
    f = findings[0]
    assert f.severity.normalized == "unknown"
    assert f.severity.by_source == (("oss-policy-kit-k8s-parser", "weird"),)
    assert f.location.logical.type == "k8s-object"
    assert (f.location.logical.kind, f.location.logical.namespace, f.location.logical.name) == (
        "Deployment",
        "prod",
        "api",
    )
    assert f.severity.normalized in fn.NORMALIZED_SEVERITIES


# --------------------------------------------------------------------------- #
# honest source records
# --------------------------------------------------------------------------- #


def test_all_sources_missing_yields_six_honest_records(tmp_path: Path) -> None:
    findings, records = fn.normalize_kit_evidence(tmp_path)
    assert findings == []
    assert len(records) == len(fn.KIT_EVIDENCE_SOURCES) == 6
    assert {r.status for r in records} == {"missing"}
    assert {r.kind for r in records} == {"kit-evidence"}


def test_oversize_evidence_is_recorded_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_evidence(tmp_path, "iac-cfn.json", _envelope("oss-policy-kit-cfn-parser", []))
    monkeypatch.setattr(fn, "MAX_EVIDENCE_BYTES", 4)
    findings, records = fn.normalize_kit_evidence(tmp_path)
    cfn = next(r for r in records if r.path.endswith("iac-cfn.json"))
    assert cfn.status == "oversize"
    assert findings == []


def test_utf16_evidence_is_unreadable_not_a_crash(tmp_path: Path) -> None:
    d = tmp_path / _EVID
    d.mkdir(parents=True)
    (d / "iac-bicep.json").write_text('{"findings": []}', encoding="utf-16")
    _, records = fn.normalize_kit_evidence(tmp_path)
    bicep = next(r for r in records if r.path.endswith("iac-bicep.json"))
    assert bicep.status == "unreadable"


def test_scanner_reported_status_propagates(tmp_path: Path) -> None:
    _write_evidence(tmp_path, "sast-semgrep.json", _envelope("semgrep", [], status="not_available"))
    _write_evidence(tmp_path, "iac-terraform.json", _envelope("oss-policy-kit-iac-parser", [], status="bogus"))
    _, records = fn.normalize_kit_evidence(tmp_path)
    by_name = {r.path.rsplit("/", 1)[-1]: r for r in records}
    assert by_name["sast-semgrep.json"].status == "not_available"
    assert by_name["iac-terraform.json"].status == "error"  # unknown scanner status -> error


def test_normalization_is_deterministic(tmp_path: Path) -> None:
    _write_evidence(
        tmp_path,
        "iac-terraform.json",
        _envelope(
            "oss-policy-kit-iac-parser",
            [
                {
                    "rule_id": "IAC-TF-002",
                    "severity": "LOW",
                    "message": "m1",
                    "file": "a.tf",
                    "resource_type": "t",
                    "resource_name": "x",
                },
                {
                    "rule_id": "IAC-TF-001",
                    "severity": "HIGH",
                    "message": "m2",
                    "file": "b.tf",
                    "resource_type": "t",
                    "resource_name": "y",
                },
            ],
        ),
    )
    first = fn.normalize_kit_evidence(tmp_path)
    second = fn.normalize_kit_evidence(tmp_path)
    assert first == second
    assert [f.rule for f in first[0]] == ["IAC-TF-002", "IAC-TF-001"]  # in-file order kept


# --------------------------------------------------------------------------- #
# scanner-side: pulumi line fix + semgrep schema (authored in this slice)
# --------------------------------------------------------------------------- #


def test_pulumi_scanner_captures_line_start(tmp_path: Path) -> None:
    (tmp_path / "infra.py").write_text(
        "import pulumi_aws as aws\n\nb = aws.s3.Bucket('logs', acl='public-read')\n",
        encoding="utf-8",
    )
    outcome = pulumi.run_scan(tmp_path)
    assert outcome.findings, "expected the public-acl finding"
    assert outcome.findings[0].line_start == 3
    payload = pulumi.render_evidence_payload(outcome, target=tmp_path)
    assert payload["findings"][0]["line_start"] == 3
    schema = json.loads(
        (ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "evidence-iac-pulumi.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(schema).validate(payload)


def test_semgrep_payload_validates_against_new_schema() -> None:
    outcome = semgrep_adapter.SemgrepRunOutcome(
        status="ok",
        version="1.100.0",
        rulesets=["p/security-audit"],
        findings=[
            semgrep_adapter.SemgrepFinding(
                rule_id="python.lang.security.dangerous-eval",
                severity="ERROR",
                message="eval() on user input",
                file="app/main.py",
                line_start=10,
                line_end=12,
                cwe=["CWE-95"],
                owasp=["A03:2021"],
            )
        ],
        scanned_at="2026-06-10T00:00:00Z",
    )
    payload = semgrep_adapter.render_evidence_payload(outcome, target=Path("."))
    schema = json.loads(
        (ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "evidence-sast-semgrep.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(schema).validate(payload)
