"""Tests for the ``ingest-insights`` subcommand (ADR-032).

Covers the exit-code contract (0 valid/not-found, 1 invalid, 2 usage), the
self-reported provenance label, signal extraction, schema-version warnings,
discovery locations, and the emit -> ingest round-trip that pins the
producer/consumer contract.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from typer.testing import CliRunner

from oss_policy_kit.cli import ingest_insights as ii
from oss_policy_kit.cli.main import app

runner = CliRunner()


def _valid_doc() -> dict[str, Any]:
    return {
        "header": {
            "schema-version": "1.0.0",
            "last-updated": "2026-05-29T00:00:00Z",
            "url": "https://github.com/org/repo",
        },
        "project-lifecycle": {"status": "active", "bug-fixes-only": False},
        "contribution-policy": {"accepts-pull-requests": True},
        "vulnerability-reporting": {
            "accepts-vulnerability-reports": True,
            "security-policy": "https://github.com/org/repo/blob/main/SECURITY.md",
            "email-contact": "security@example.com",
        },
        "security-contacts": [{"type": "email", "value": "security@example.com"}],
        "dependencies": {"env-dependencies-policy": {"comment": "automated"}},
        "distribution-points": ["https://pypi.org/project/example/"],
    }


def _write_insights(root: Path, doc: dict[str, Any], rel: str = "SECURITY-INSIGHTS.yml") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


def _run_json(target: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    res = runner.invoke(app, ["ingest-insights", "--target", str(target), "--format", "json", *extra])
    payload = json.loads(res.output) if res.output.strip() else {}
    return res.exit_code, payload


# --- exit-code contract ------------------------------------------------------


def test_ingest_valid_file_exit_0(tmp_path: Path) -> None:
    _write_insights(tmp_path, _valid_doc())
    code, payload = _run_json(tmp_path)
    assert code == 0
    assert payload["found"] is True
    assert payload["valid"] is True
    assert payload["provenance"] == "self-reported"
    assert payload["input_path"] == "SECURITY-INSIGHTS.yml"
    assert payload["declared_schema_version"] == "1.0.0"


def test_ingest_not_found_exit_0(tmp_path: Path) -> None:
    code, payload = _run_json(tmp_path)
    assert code == 0
    assert payload["found"] is False
    assert payload["valid"] is False
    assert payload["signals"] == {}


def test_ingest_invalid_structure_exit_1(tmp_path: Path) -> None:
    # Missing project-lifecycle and header required fields.
    _write_insights(tmp_path, {"header": {"url": "x"}})
    code, payload = _run_json(tmp_path)
    assert code == 1
    assert payload["found"] is True
    assert payload["valid"] is False
    assert any("project-lifecycle" in e for e in payload["validation_errors"])
    assert any("schema-version" in e for e in payload["validation_errors"])


def test_ingest_input_override_missing_exit_2(tmp_path: Path) -> None:
    res = runner.invoke(
        app,
        ["ingest-insights", "--target", str(tmp_path), "--input", str(tmp_path / "nope.yml")],
    )
    assert res.exit_code == 2


def test_ingest_target_not_dir_exit_2(tmp_path: Path) -> None:
    res = runner.invoke(app, ["ingest-insights", "--target", str(tmp_path / "missing")])
    assert res.exit_code == 2


def test_ingest_bad_format_exit_2(tmp_path: Path) -> None:
    _write_insights(tmp_path, _valid_doc())
    res = runner.invoke(app, ["ingest-insights", "--target", str(tmp_path), "--format", "xml"])
    assert res.exit_code == 2


def test_ingest_malformed_root_not_mapping_exit_1(tmp_path: Path) -> None:
    (tmp_path / "SECURITY-INSIGHTS.yml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    code, payload = _run_json(tmp_path)
    assert code == 1
    assert payload["found"] is True
    assert payload["valid"] is False
    assert payload["validation_errors"]


def test_ingest_unparseable_yaml_exit_1(tmp_path: Path) -> None:
    (tmp_path / "SECURITY-INSIGHTS.yml").write_text("key: : : not yaml\n  - broken", encoding="utf-8")
    code, payload = _run_json(tmp_path)
    assert code == 1
    assert payload["valid"] is False


# --- warnings vs errors ------------------------------------------------------


def test_ingest_schema_version_mismatch_is_warning_not_error(tmp_path: Path) -> None:
    doc = _valid_doc()
    doc["header"]["schema-version"] = "2.0.0"
    _write_insights(tmp_path, doc)
    code, payload = _run_json(tmp_path)
    assert code == 0  # warning does not fail
    assert payload["valid"] is True
    assert payload["validation_errors"] == []
    assert any("2.0.0" in w for w in payload["validation_warnings"])
    assert payload["declared_schema_version"] == "2.0.0"


# --- signal extraction -------------------------------------------------------


def test_ingest_extracts_expected_signals(tmp_path: Path) -> None:
    _write_insights(tmp_path, _valid_doc())
    _code, payload = _run_json(tmp_path)
    s = payload["signals"]
    assert s["project_lifecycle_status"] == "active"
    assert s["accepts_vulnerability_reports"] is True
    assert s["security_policy_url"].endswith("SECURITY.md")
    assert "security@example.com" in s["security_contacts"]
    assert s["accepts_pull_requests"] is True
    assert s["has_dependency_automation_policy"] is True
    assert s["distribution_points"] == ["https://pypi.org/project/example/"]


# --- discovery ---------------------------------------------------------------


def test_ingest_discovers_github_location(tmp_path: Path) -> None:
    _write_insights(tmp_path, _valid_doc(), rel=".github/SECURITY-INSIGHTS.yml")
    code, payload = _run_json(tmp_path)
    assert code == 0
    assert payload["found"] is True
    assert payload["input_path"] == ".github/SECURITY-INSIGHTS.yml"


def test_ingest_discovers_kit_lowercase_emit_name(tmp_path: Path) -> None:
    _write_insights(tmp_path, _valid_doc(), rel="security-insights.yml")
    code, payload = _run_json(tmp_path)
    assert code == 0
    assert payload["input_path"] == "security-insights.yml"


def test_ingest_input_override_is_used(tmp_path: Path) -> None:
    custom = _write_insights(tmp_path, _valid_doc(), rel="sub/custom-insights.yaml")
    res = runner.invoke(
        app,
        ["ingest-insights", "--target", str(tmp_path), "--input", str(custom), "--format", "json"],
    )
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["found"] is True


def test_ingest_path_with_spaces_and_unicode(tmp_path: Path) -> None:
    weird = tmp_path / "wéird dir — ç@#"
    weird.mkdir()
    _write_insights(weird, _valid_doc())
    code, payload = _run_json(weird)
    assert code == 0
    assert payload["valid"] is True


# --- human output ------------------------------------------------------------


def test_ingest_human_output_carries_provenance_caveat(tmp_path: Path) -> None:
    _write_insights(tmp_path, _valid_doc())
    res = runner.invoke(app, ["ingest-insights", "--target", str(tmp_path)])
    assert res.exit_code == 0
    assert "self-reported" in res.output
    assert "NOT independently verified" in res.output
    assert "does not change any" in res.output


def test_ingest_human_not_found_message(tmp_path: Path) -> None:
    res = runner.invoke(app, ["ingest-insights", "--target", str(tmp_path)])
    assert res.exit_code == 0
    assert "none found" in res.output


# --- emit -> ingest round-trip (producer/consumer contract) ------------------


def test_emit_then_ingest_roundtrip(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text("Report to security@example.com\n", encoding="utf-8")
    (repo / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    emitted = tmp_path / "security-insights.yml"
    emit_res = runner.invoke(app, ["emit-insights", "--target", str(repo), "--output", str(emitted)])
    assert emit_res.exit_code == 0, emit_res.output
    # Ingest the very document emit-insights produced: it must validate cleanly.
    res = runner.invoke(
        app,
        ["ingest-insights", "--target", str(repo), "--input", str(emitted), "--format", "json"],
    )
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["valid"] is True
    assert payload["validation_errors"] == []
    assert payload["signals"]["accepts_vulnerability_reports"] is True


# --- unit-level helpers ------------------------------------------------------


def test_validate_ingest_structure_accepts_minimal() -> None:
    errors, warnings = ii._validate_ingest_structure(
        {"header": {"schema-version": "1.0.0", "last-updated": "x"}, "project-lifecycle": {"status": "active"}}
    )
    assert errors == []
    assert warnings == []


def test_validate_ingest_structure_flags_missing_header() -> None:
    errors, _warnings = ii._validate_ingest_structure({"project-lifecycle": {"status": "active"}})
    assert any("header" in e for e in errors)


def test_discover_prefers_canonical_over_github(tmp_path: Path) -> None:
    _write_insights(tmp_path, _valid_doc(), rel="SECURITY-INSIGHTS.yml")
    _write_insights(tmp_path, _valid_doc(), rel=".github/SECURITY-INSIGHTS.yml")
    found = ii._discover_insights_file(tmp_path)
    assert found is not None and found.name == "SECURITY-INSIGHTS.yml"
    assert found.parent == tmp_path


def test_security_contacts_dedupes_email_contact() -> None:
    doc = {
        "security-contacts": [{"type": "email", "value": "a@example.com"}],
        "vulnerability-reporting": {"email-contact": "a@example.com"},
    }
    assert ii._security_contacts(doc) == ["a@example.com"]


def test_extract_signals_tolerates_missing_sections() -> None:
    signals = ii._extract_signals({"header": {"schema-version": "1.0.0"}})
    assert signals["project_lifecycle_status"] is None
    assert signals["accepts_vulnerability_reports"] is None
    assert signals["security_contacts"] == []
    assert signals["has_dependency_automation_policy"] is False
    assert signals["distribution_points"] == []
