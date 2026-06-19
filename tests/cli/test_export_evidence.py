"""export-evidence subcommand: format registry + Chainloop renderer (PR-17, ADR-012)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.cli.export_evidence import (
    _INTOTO_PREDICATE_TYPE,
    _RENDERERS,
    _SUPPORTED_FORMATS,
    _load_evaluation_report,
    _render_chainloop,
    _render_gemara,
    _render_intoto_bundle,
    _render_oscal,
    _render_sarif,
    _render_spdx,
    _validate,
)
from oss_policy_kit.domain.errors import InvalidInputError


def _sample_report() -> dict:
    return {
        "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/1.0",
        "target": "examples/hardened-repo",
        "profile": {"id": "github-level-1"},
        "summary_by_status": {"pass": 8, "fail": 1, "manual-review-required": 2},
        "controls": [
            {"id": "GOV-SEC-001", "status": "pass", "reason": "SECURITY.md present."},
            {"id": "GH-PROV-023", "status": "manual-review-required", "reason": "No evidence file."},
        ],
        "waivers": [],
    }


def test_supported_formats_present() -> None:
    assert set(_RENDERERS.keys()) == set(_SUPPORTED_FORMATS)


def test_render_chainloop_envelope_shape() -> None:
    out = _render_chainloop(_sample_report())
    assert out["attestation_type"].startswith("https://chainloop.dev/")
    assert out["subject"]["kit"] == "oss-policy-kit"
    assert out["subject"]["profile"] == "github-level-1"
    assert out["experimental"] is True
    assert "predicate" in out and "evaluatedAt" in out["predicate"]


def test_render_chainloop_passes_validation() -> None:
    out = _render_chainloop(_sample_report())
    assert _validate(out, "chainloop") == []


def test_render_chainloop_validation_catches_missing_fields() -> None:
    errs = _validate({"attestation_type": "x"}, "chainloop")
    assert any("subject" in e for e in errs)
    assert any("predicate" in e for e in errs)


def test_render_sarif_synthesises_from_controls() -> None:
    out = _render_sarif(_sample_report())
    assert out["version"] == "2.1.0"
    assert isinstance(out["runs"], list) and len(out["runs"]) == 1
    results = out["runs"][0]["results"]
    assert len(results) == 2
    assert any(r["ruleId"] == "GOV-SEC-001" for r in results)
    assert _validate(out, "sarif") == []


def test_render_sarif_uses_existing_runs_when_present() -> None:
    report = _sample_report()
    report["sarif_runs"] = [{"tool": {"driver": {"name": "existing"}}, "results": []}]
    out = _render_sarif(report)
    assert out["runs"][0]["tool"]["driver"]["name"] == "existing"


def test_load_evaluation_report_finds_explicit_path(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(_sample_report()), encoding="utf-8")
    data = _load_evaluation_report(tmp_path, report_file)
    assert data["target"] == "examples/hardened-repo"


def test_load_evaluation_report_falls_back_to_target_out(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "evaluation-report.json").write_text(json.dumps(_sample_report()), encoding="utf-8")
    data = _load_evaluation_report(tmp_path, None)
    assert data["profile"]["id"] == "github-level-1"


def test_load_evaluation_report_raises_when_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Chdir into the empty tmp_path so the cwd fallback also misses.
    monkeypatch.chdir(tmp_path)
    with pytest.raises(InvalidInputError, match="No evaluation report found"):
        _load_evaluation_report(tmp_path, None)


def test_chainloop_format_is_marked_experimental() -> None:
    """The output must self-declare as experimental so downstream consumers can branch."""
    out = _render_chainloop(_sample_report())
    assert out.get("experimental") is True
    assert "experimental_note" in out


# --- v7.0.0 GA formats: spdx / oscal / in-toto-bundle (ADR-034, ADR-036) -------------


def test_spdx_and_oscal_and_intoto_are_registered() -> None:
    for fmt in ("spdx", "oscal", "in-toto-bundle"):
        assert fmt in _SUPPORTED_FORMATS
        assert fmt in _RENDERERS
    # guac stays deferred (ADR-036): must NOT be registered.
    assert "guac" not in _SUPPORTED_FORMATS


def test_render_spdx_shape_and_validation() -> None:
    out = _render_spdx(_sample_report())
    assert out["spdxVersion"] == "SPDX-2.3"
    assert out["SPDXID"] == "SPDXRef-DOCUMENT"
    assert out["packages"][0]["name"] == "examples/hardened-repo"
    # one annotation per control
    assert len(out["packages"][0]["annotations"]) == 2
    # honesty caveat: explicitly not a dependency SBOM
    assert "NOT a dependency" in out["creationInfo"]["comment"]
    assert _validate(out, "spdx") == []


def test_render_spdx_validation_catches_missing_fields() -> None:
    errs = _validate({"spdxVersion": "SPDX-2.2"}, "spdx")
    assert any("spdxVersion" in e for e in errs)
    assert any("packages" in e for e in errs)


def test_render_oscal_shape_and_validation() -> None:
    out = _render_oscal(_sample_report())
    ar = out["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert len(ar["results"][0]["observations"]) == 2
    assert _validate(out, "oscal") == []


def test_render_oscal_validation_catches_missing_results() -> None:
    errs = _validate({"assessment-results": {"metadata": {}}}, "oscal")
    assert any("results" in e for e in errs)


def test_render_oscal_carries_assurance_subject_and_log() -> None:
    """T2.2: each observation carries the kit assurance grade + state; the result carries a
    repo subject and an assessment-log."""
    report = {
        "target": "examples/hardened-repo",
        "profile": {"id": "github-level-1"},
        "controls": [
            {"id": "GOV-SEC-001", "state": "PASS", "status": "pass", "assurance": "deterministic", "reason": "ok"},
            {"id": "GH-PROV-023", "state": "UNKNOWN", "status": "manual-review-required", "assurance": "signal"},
        ],
    }
    out = _render_oscal(report)
    result = out["assessment-results"]["results"][0]
    obs = result["observations"]
    assert len(obs) == 2
    assert obs[0]["methods"] == ["EXAMINE"]  # examines artifacts, does not run tests
    props = {p["name"]: p["value"] for p in obs[0]["props"]}
    assert props["assurance"] == "deterministic" and props["kit-state"] == "PASS"
    assert obs[0]["subjects"][0]["subject-uuid"]  # points at a defined subject
    # the result references the evaluated repo and logs the run
    subj = result["assessment-subjects"][0]
    assert "examples/hardened-repo" in subj["description"]
    assert result["assessment-log"]["entries"][0]["title"]
    assert _validate(out, "oscal") == []


def test_render_oscal_validation_catches_missing_log() -> None:
    errs = _validate({"assessment-results": {"metadata": {}, "results": [{"observations": []}]}}, "oscal")
    assert any("assessment-subjects" in e for e in errs)
    assert any("assessment-log" in e for e in errs)


# --- v8.1.0: Gemara Layer 5 Evaluation Log (ADR-042) ---------------------------------


def test_gemara_is_registered() -> None:
    assert "gemara" in _SUPPORTED_FORMATS
    assert "gemara" in _RENDERERS


def test_render_gemara_maps_states_grades_and_validates() -> None:
    report = {
        "target": "examples/hardened-repo",
        "profile": {"id": "github-level-1"},
        "controls": [
            {"id": "GOV-SEC-001", "state": "PASS", "assurance": "deterministic", "reason": "present"},
            {"id": "GH-PROV-023", "state": "UNKNOWN", "assurance": "signal", "reason": "no evidence"},
            {"id": "X-NA-001", "state": "NOT_APPLICABLE", "assurance": "signal"},
            {"id": "Y-FAIL-001", "state": "FAIL", "assurance": "deterministic", "reason": "bad"},
        ],
    }
    doc = _render_gemara(report)
    assert doc["metadata"]["type"] == "EvaluationLog"
    assert doc["metadata"]["gemara-version"]  # pinned pre-1.0 model version
    assert doc["target"]["name"] == "examples/hardened-repo"
    by_name = {e["name"]: e for e in doc["evaluations"]}
    assert by_name["GOV-SEC-001"]["result"] == "Passed"
    assert by_name["GH-PROV-023"]["result"] == "Needs Review"
    assert by_name["X-NA-001"]["result"] == "Not Applicable"
    assert by_name["Y-FAIL-001"]["result"] == "Failed"
    # assurance grade -> Gemara ConfidenceLevel
    assert by_name["GOV-SEC-001"]["assessment-logs"][0]["confidence-level"] == "High"
    assert by_name["GH-PROV-023"]["assessment-logs"][0]["confidence-level"] == "Medium"
    # aggregate is the worst-case (a Failed present)
    assert doc["result"] == "Failed"
    # requirement reference-id matches the control reference-id (Gemara constraint)
    ev = by_name["GOV-SEC-001"]
    assert ev["control"]["reference-id"] == ev["assessment-logs"][0]["requirement"]["reference-id"]
    assert _validate(doc, "gemara") == []


def test_validate_gemara_catches_bad_docs() -> None:
    assert any("evaluations" in e for e in _validate({"metadata": {"type": "EvaluationLog"}}, "gemara"))
    bad = {
        "metadata": {"type": "EvaluationLog", "gemara-version": "v0"},
        "target": {},
        "result": "Passed",
        "evaluations": [{"name": "A", "result": "Bogus", "assessment-logs": [{}]}],
    }
    assert any("invalid result" in e for e in _validate(bad, "gemara"))


def test_render_intoto_bundle_shape_and_validation() -> None:
    out = _render_intoto_bundle(_sample_report())
    assert out["_type"] == "https://in-toto.io/Statement/v1"
    assert out["predicateType"] == _INTOTO_PREDICATE_TYPE
    assert out["subject"][0]["name"] == "examples/hardened-repo"
    # subject is name-only: no fabricated digest (honest provenance)
    assert "digest" not in out["subject"][0]
    # unsigned in v7.0.0; signing is the v8 ATTESTED track
    assert out["predicate"]["signed"] is False
    assert _validate(out, "in-toto-bundle") == []


def test_render_intoto_validation_catches_bad_type() -> None:
    errs = _validate({"_type": "wrong", "subject": [], "predicate": {}}, "in-toto-bundle")
    assert any("_type" in e for e in errs)
    assert any("subject" in e for e in errs)
