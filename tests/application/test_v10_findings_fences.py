"""v10.0.0 fence tests (ADR-030 scope-gate demands D5/D6/D8 + anti-ASPM).

FT-3: vulnerability_ids-keyed waivers never change any control state,
      summary_by_status, or results_digest; control-keyed parsing is
      byte-identical after the A-S7 hoist; the findings gate respects waivers.
FT-4: an enrichment snapshot affects ONLY priority.rank/rationale — never a
      finding's kev/epss/severity fields, and control results are untouched.
FT-5: the SARIF export self-describes as an aggregator with mandatory
      per-result source-tool attribution.
FT-6: correlate-findings re-runs bit-identically on an unchanged clone.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import Result
from tests.conftest import EXAMPLE_HARDENED
from typer.testing import CliRunner

from oss_policy_kit.application import vuln_waivers as vw
from oss_policy_kit.application.findings_report import build_findings_report
from oss_policy_kit.application.findings_sarif_export import render_findings_sarif
from oss_policy_kit.application.reporting import report_to_dict
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli import emit_vex
from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()
_EVID = Path(".oss-policy-kit") / "evidence"

_MIXED_WAIVERS = """\
waivers:
  - control_id: GOV-SEC-001
    owner: appsec
    justification: control-gate waiver
    expires_at: 2099-12-31
  - vulnerability_ids: [CVE-2026-1]
    owner: appsec
    justification: vuln-keyed waiver for the findings surface
    expires_at: 2099-12-31
"""

_CONTROL_ONLY_WAIVERS = """\
waivers:
  - control_id: GOV-SEC-001
    owner: appsec
    justification: control-gate waiver
    expires_at: 2099-12-31
"""


def _invoke(args: list[str]) -> Result:
    return runner.invoke(app, prepare_cli_args(args))


def _write_osv(repo: Path, *, kev: bool = True) -> None:
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "osv-scanner", "version": "2.0.0"}},
                "results": [
                    {
                        "ruleId": "CVE-2026-1",
                        "level": "error",
                        "message": {"text": "vulnerable dep"},
                        "properties": ({"kev": "true", "cve": "CVE-2026-1"} if kev else {"cve": "CVE-2026-1"}),
                    },
                    {
                        "ruleId": "GHSA-zzzz",
                        "level": "warning",
                        "message": {"text": "second vuln"},
                        "properties": {},
                    },
                ],
            }
        ],
    }
    p = repo / _EVID / "sast" / "osv-scanner.sarif.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc), encoding="utf-8")


# --------------------------------------------------------------------------- #
# FT-3 — waiver fences
# --------------------------------------------------------------------------- #


def test_ft3_vuln_waivers_never_touch_the_evaluation_report(tmp_path: Path) -> None:
    """A vuln-keyed waiver entry must leave the evaluate report byte-identical."""
    from oss_policy_kit.application.engine import evaluate_repository
    from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id

    mixed = tmp_path / "mixed.yaml"
    mixed.write_text(_MIXED_WAIVERS, encoding="utf-8")
    control_only = tmp_path / "control.yaml"
    control_only.write_text(_CONTROL_ONLY_WAIVERS, encoding="utf-8")

    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, "github-level-1")

    def _payload(waiver_file: Path) -> dict:
        report = evaluate_repository(
            repo_root=EXAMPLE_HARDENED,
            profile=profile,
            catalog=catalog,
            waiver_outcome=parse_waivers_file(waiver_file),
            scorecard=None,
        )
        return report_to_dict(report)

    a = _payload(mixed)
    b = _payload(control_only)
    assert a["summary_by_status"] == b["summary_by_status"]
    assert a["results_digest"] == b["results_digest"]
    assert [c["state"] for c in a["controls"]] == [c["state"] for c in b["controls"]]


def test_ft3_hoisted_parser_is_the_same_object() -> None:
    """emit-vex consumes the SAME hoisted parser (behavior byte-identical by identity)."""
    assert emit_vex._load_vuln_waivers is vw.load_vuln_waivers
    assert emit_vex._VulnWaiver is vw.VulnWaiver


def test_ft3_cross_parser_split_over_one_mixed_file(tmp_path: Path) -> None:
    mixed = tmp_path / "waivers.yaml"
    mixed.write_text(_MIXED_WAIVERS, encoding="utf-8")
    control_outcome = parse_waivers_file(mixed)
    assert list(control_outcome.by_control) == ["GOV-SEC-001"]
    vuln_map, _ = vw.load_vuln_waivers(mixed)
    assert set(vuln_map) == {"CVE-2026-1"}


def test_ft3_findings_gate_respects_vuln_waiver(tmp_path: Path) -> None:
    _write_osv(tmp_path, kev=True)
    (tmp_path / "waivers.yaml").write_text(_MIXED_WAIVERS, encoding="utf-8")
    out = tmp_path / "f.json"
    # without waiver: KEV gate trips
    r1 = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--fail-on-kev"])
    assert r1.exit_code == 1
    # with waiver: gate passes, finding stays visible and carries the waiver block
    r2 = _invoke(
        [
            "correlate-findings",
            "--target",
            str(tmp_path),
            "--output",
            str(out),
            "--fail-on-kev",
            "--waivers",
            "waivers.yaml",
        ]
    )
    assert r2.exit_code == 0, r2.output
    artifact = json.loads(out.read_text(encoding="utf-8"))
    waived = next(f for f in artifact["findings"] if "CVE-2026-1" in f["vulnerability_ids"])
    assert waived["waiver"]["waived"] is True
    assert waived["waiver"]["matched_by"] == "vulnerability_id"
    assert waived["waiver"]["waiver_owner"] == "appsec"


# --------------------------------------------------------------------------- #
# FT-4 — enrichment is ranking-only
# --------------------------------------------------------------------------- #


def test_ft4_enrichment_moves_rank_only(tmp_path: Path) -> None:
    _write_osv(tmp_path, kev=False)  # no kev/epss reported by the source
    snapshot = tmp_path / "enrich.json"
    snapshot.write_text(
        json.dumps({"as_of": "2026-06-01", "vulnerabilities": {"GHSA-zzzz": {"epss": 0.99, "kev": True}}}),
        encoding="utf-8",
    )
    plain = build_findings_report(tmp_path, kit_version="10.0.0", generated_at="t")
    enriched = build_findings_report(tmp_path, kit_version="10.0.0", generated_at="t", enrichment_path=snapshot)

    def by_vid(rep: dict, vid: str) -> dict:
        return next(f for f in rep["findings"] if vid in f["vulnerability_ids"])

    for vid in ("CVE-2026-1", "GHSA-zzzz"):
        p, e = by_vid(plain, vid), by_vid(enriched, vid)
        # fields NEVER change (D6): kev/epss/cvss/severity identical
        assert (p["kev"], p["epss"], p["cvss"]) == (e["kev"], e["epss"], e["cvss"])
        assert p["severity"] == e["severity"]
    # but the snapshot re-ranks: GHSA-zzzz (KEV+EPSS via snapshot) now outranks
    assert by_vid(enriched, "GHSA-zzzz")["priority"]["rank"] == 1
    assert "(snapshot)" in by_vid(enriched, "GHSA-zzzz")["priority"]["rationale"]
    # provenance recorded with inferred-trust label + as-of date
    rec = next(r for r in enriched["sources_read"] if r["kind"] == "enrichment-snapshot")
    assert rec["status"] == "ok"
    assert "inferred trust" in rec["tool"]
    assert rec["tool_version"] == "2026-06-01"
    # by_severity totals unchanged
    assert plain["findings_by_severity"] == enriched["findings_by_severity"]


def test_ft4_unreadable_snapshot_is_honest_not_fatal(tmp_path: Path) -> None:
    _write_osv(tmp_path)
    bad = tmp_path / "enrich.json"
    bad.write_text('{"vulnerabilities": ', encoding="utf-8")  # truncated JSON
    report = build_findings_report(tmp_path, kit_version="10.0.0", generated_at="t", enrichment_path=bad)
    rec = next(r for r in report["sources_read"] if r["kind"] == "enrichment-snapshot")
    assert rec["status"] == "unreadable"
    assert report["findings_total"] == 2  # findings unaffected


# --------------------------------------------------------------------------- #
# FT-5 — SARIF export attribution (D8)
# --------------------------------------------------------------------------- #


def test_ft5_sarif_export_attributes_every_result(tmp_path: Path) -> None:
    _write_osv(tmp_path)
    report = build_findings_report(tmp_path, kit_version="10.0.0", generated_at="t")
    sarif = render_findings_sarif(report)
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "oss-policy-kit correlate-findings"
    assert "not a scanner" in driver["shortDescription"]["text"]
    assert run["properties"]["role"] == "aggregator"
    assert "double-report" in run["properties"]["double_reporting_note"]
    assert run["results"], "expected results"
    for result in run["results"]:
        assert result["properties"]["source_tools"] == ["osv-scanner"]
        assert result["properties"]["source_paths"] == [".oss-policy-kit/evidence/sast/osv-scanner.sarif.json"]
        assert result["partialFingerprints"]["findingFingerprint/v1"].startswith("opk-fk/v1:")
    rule_ids = {r["id"] for r in driver["rules"]}
    assert {res["ruleId"] for res in run["results"]} <= rule_ids


def test_ft5_cli_format_sarif_emits_sarif(tmp_path: Path) -> None:
    _write_osv(tmp_path)
    out = tmp_path / "f.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out), "--format", "sarif"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.output)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["properties"]["role"] == "aggregator"
    # the findings/1.0 artifact is still written to --output
    assert json.loads(out.read_text(encoding="utf-8"))["contract_version"] == "findings/1.0"


# --------------------------------------------------------------------------- #
# FT-6 — re-runs are bit-identical (anti-ASPM: no hidden state)
# --------------------------------------------------------------------------- #


def test_ft6_reruns_are_bit_identical(tmp_path: Path) -> None:
    _write_osv(tmp_path)
    out = tmp_path / "f.json"
    _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out)])
    first = out.read_bytes()
    _invoke(["correlate-findings", "--target", str(tmp_path), "--output", str(out)])
    assert out.read_bytes() == first
