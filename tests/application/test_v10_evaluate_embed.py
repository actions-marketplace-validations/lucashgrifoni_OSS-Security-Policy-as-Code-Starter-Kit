"""A-S8 (ADR-030): the flag-gated evaluate --with-findings-summary embed + FT-1/FT-2.

FT-1: with the flag OFF, evaluate output is byte-identical whether or not a
      (stale or fresh) findings.json exists next to the report, and no evaluate
      code path opens .oss-policy-kit/findings.json.
FT-2: control states, summary_by_status, results_digest, and exit codes are
      identical with the flag ON vs OFF — the embed is additive only.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import Result
from tests.conftest import ROOT
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()


def _invoke(args: list[str]) -> Result:
    return runner.invoke(app, prepare_cli_args(args))


def _github_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    return repo


def _evaluate(repo: Path, out: Path, *extra: str) -> Result:
    return _invoke(
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(out),
            "--fail-on",
            "none",
            "--quiet",
            *extra,
        ]
    )


def test_ft1_flag_off_is_byte_identical_despite_findings_artifact(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    out1 = tmp_path / "out1"
    r1 = _evaluate(repo, out1)
    assert r1.exit_code == 0, r1.output
    baseline = (out1 / "evaluation-report.json").read_bytes()

    # Plant a stale findings artifact next to the evidence — evaluate must not read it.
    stale = repo / ".oss-policy-kit" / "findings.json"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"bogus": "stale artifact from a previous run"}', encoding="utf-8")
    out2 = tmp_path / "out2"
    r2 = _evaluate(repo, out2)
    assert r2.exit_code == 0, r2.output
    assert (out2 / "evaluation-report.json").read_bytes() == baseline


def test_ft1_no_evaluate_code_path_opens_findings_json() -> None:
    """Source-level guard: the evaluate implementation never references findings.json."""
    for rel in ("src/oss_policy_kit/cli/common.py", "src/oss_policy_kit/cli/evaluate.py"):
        source = (ROOT / rel).read_text(encoding="utf-8")
        assert "findings.json" not in source, f"{rel} must not reference the findings artifact"


def test_ft2_embed_is_additive_only(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    out_off = tmp_path / "off"
    out_on = tmp_path / "on"
    r_off = _evaluate(repo, out_off)
    r_on = _evaluate(repo, out_on, "--with-findings-summary")
    assert r_off.exit_code == r_on.exit_code == 0

    off = json.loads((out_off / "evaluation-report.json").read_text(encoding="utf-8"))
    on = json.loads((out_on / "evaluation-report.json").read_text(encoding="utf-8"))
    assert off["summary_by_status"] == on["summary_by_status"]
    assert off["results_digest"] == on["results_digest"]
    assert [c["state"] for c in off["controls"]] == [c["state"] for c in on["controls"]]
    # the ONLY difference is the additive extensions block
    assert off["extensions"] == {}
    summary = on["extensions"]["findings_summary"]
    assert set(summary) == {
        "findings_total",
        "correlated_groups",
        "by_severity",
        "kev_count",
        "high_epss_count",
        "artifact",
        "findings_digest",
    }
    off.pop("extensions")
    on.pop("extensions")
    assert off == on


def test_embed_counts_real_findings(tmp_path: Path) -> None:
    repo = _github_repo(tmp_path)
    evid = repo / ".oss-policy-kit" / "evidence"
    evid.mkdir(parents=True)
    (evid / "iac-terraform.json").write_text(
        json.dumps(
            {
                "schema_version": "oss-policy-kit/evidence/iac-terraform/v1",
                "tool": "oss-policy-kit-iac-parser",
                "status": "ok",
                "target": "x",
                "scanned_at": "t",
                "attested_at": "2026-06-10",
                "attested_by": "t",
                "findings_total": 1,
                "findings": [
                    {
                        "rule_id": "IAC-TF-001",
                        "severity": "CRITICAL",
                        "message": "public bucket",
                        "file": "main.tf",
                        "resource_type": "aws_s3_bucket",
                        "resource_name": "logs",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = _evaluate(repo, out, "--with-findings-summary")
    assert result.exit_code == 0, result.output
    payload = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    summary = payload["extensions"]["findings_summary"]
    assert summary["findings_total"] == 1
    assert summary["by_severity"]["critical"] == 1
    assert len(summary["findings_digest"]) == 16
