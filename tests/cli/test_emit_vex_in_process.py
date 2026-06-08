"""In-process branch coverage for ``emit-vex``.

The existing ``test_emit_vex_openvex.py`` exercises the CLI through ``subprocess``
(a separate interpreter), so those paths never reach the coverage measurement of
the test process. This file drives the same surface **in-process** — calling
``_run_emit_vex`` / ``_write_vex_output`` directly and the Typer command via
``CliRunner`` — so ``_run_emit_vex``, the OpenVEX/CycloneDX branches, the write
path, and the structural validators are measured.

All inputs are synthetic SARIF / waiver fixtures; no network or external tools.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import emit_vex as ev
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()


def _sarif(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "osv.sarif.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _rules_sarif(tmp_path: Path, *rule_ids: str) -> Path:
    return _sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": [{"id": r} for r in rule_ids]}}, "results": []}]})


# --------------------------------------------------------------------------- #
# _extract_sarif_data — malformed-shape guards
# --------------------------------------------------------------------------- #


def test_extract_sarif_rules_not_a_list(tmp_path: Path) -> None:
    p = _sarif(tmp_path, {"runs": [{"tool": {"driver": {"rules": "nope"}}}]})
    ids, refs, err = ev._extract_sarif_data(p)
    assert err is None and ids == [] and refs == {}


def test_extract_sarif_rule_and_result_element_guards(tmp_path: Path) -> None:
    p = _sarif(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                123,  # not a dict -> skipped
                                {"id": 999},  # id not a str -> skipped
                                {"id": "   "},  # blank id -> skipped
                                {"id": "CVE-1", "helpUri": "https://osv.dev/CVE-1"},  # ref captured
                            ]
                        }
                    },
                    "results": [
                        123,  # not a dict -> skipped
                        {"ruleId": 999},  # ruleId not a str -> skipped
                        {"ruleId": "CVE-2"},  # captured
                    ],
                }
            ]
        },
    )
    ids, refs, err = ev._extract_sarif_data(p)
    assert err is None
    assert ids == ["CVE-1", "CVE-2"]
    assert refs == {"CVE-1": ["https://osv.dev/CVE-1"]}


def test_extract_sarif_results_not_a_list(tmp_path: Path) -> None:
    p = _sarif(tmp_path, {"runs": [{"results": "nope"}]})
    ids, _refs, err = ev._extract_sarif_data(p)
    assert err is None and ids == []


def test_extract_sarif_runs_not_a_list(tmp_path: Path) -> None:
    p = _sarif(tmp_path, {"runs": "nope"})
    ids, _refs, err = ev._extract_sarif_data(p)
    assert err == "SARIF 'runs' is not an array."


def test_extract_sarif_run_not_a_dict(tmp_path: Path) -> None:
    p = _sarif(tmp_path, {"runs": [123]})
    ids, _refs, err = ev._extract_sarif_data(p)
    assert err is None and ids == []


def test_extract_sarif_read_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = _sarif(tmp_path, {"runs": []})

    def _boom(self: Path, *a: object, **k: object) -> str:
        raise OSError("disk gone")

    # oversize_reason uses stat(), not read_text, so the size gate still passes
    # and we reach the read_text OSError branch.
    monkeypatch.setattr(Path, "read_text", _boom)
    ids, _refs, err = ev._extract_sarif_data(p)
    assert err is not None and "Could not read SARIF" in err


# --------------------------------------------------------------------------- #
# _load_vuln_waivers — file/shape guards and per-entry skips
# --------------------------------------------------------------------------- #


def test_load_vuln_waivers_unreadable_yaml(tmp_path: Path) -> None:
    p = tmp_path / "w.yaml"
    p.write_text("a: b: c\n", encoding="utf-8")  # invalid YAML -> YAMLError
    out, warns = ev._load_vuln_waivers(p)
    assert out == {} and any("Could not read waivers file" in m for m in warns)


def test_load_vuln_waivers_entries_not_a_list(tmp_path: Path) -> None:
    p = tmp_path / "w.yaml"
    p.write_text("waivers: 5\n", encoding="utf-8")
    out, warns = ev._load_vuln_waivers(p)
    assert out == {} and warns == []


def test_load_vuln_waivers_skips_expired_and_control_only_and_blank_ids(tmp_path: Path) -> None:
    import yaml

    entries = [
        {"control_id": "GH-WF-001"},  # no vulnerability_ids -> parsed None, skipped
        {  # expired -> skipped via _parse_waiver_expiry ok=False
            "vulnerability_ids": ["CVE-OLD"],
            "justification": "handled long ago",
            "owner": "appsec",
            "expires_at": "2000-01-01",
        },
        {  # valid, but vulnerability_ids contains non-str / blank entries to skip
            "vulnerability_ids": ["CVE-9", 123, "  "],
            "justification": "reviewed, not exploitable",
            "owner": "appsec",
        },
    ]
    p = tmp_path / "w.yaml"
    p.write_text(yaml.safe_dump({"waivers": entries}, sort_keys=False), encoding="utf-8")
    out, warns = ev._load_vuln_waivers(p)
    assert set(out) == {"CVE-9"}
    assert any("expired" in m for m in warns)


# --------------------------------------------------------------------------- #
# _build_vex_document — waiver without a CycloneDX justification enum
# --------------------------------------------------------------------------- #


def test_build_vex_document_waiver_without_justification_enum() -> None:
    w = ev._VulnWaiver(
        justification_text="not reachable",
        owner="o",
        status="approved",
        expires_at=None,
        cdx_justification=None,  # exercises the False side of the justification branch
    )
    doc = ev._build_vex_document(["CVE-A"], Path("osv.sarif.json"), waivers={"CVE-A": w})
    analysis = doc["vulnerabilities"][0]["analysis"]
    assert analysis["state"] == "not_affected"
    assert "justification" not in analysis
    assert analysis["detail"] == "not reachable"


# --------------------------------------------------------------------------- #
# _validate_openvex_statement / _validate_openvex_structure — error branches
# --------------------------------------------------------------------------- #


def test_validate_openvex_statement_not_a_dict() -> None:
    assert ev._validate_openvex_statement(0, "nope") == ["statements[0] must be an object"]


def test_validate_openvex_statement_field_errors() -> None:
    bad = {
        "vulnerability": {"name": "  "},  # blank name
        "products": [{"@id": ""}],  # blank product @id
        "status": "bogus",  # not in status set
    }
    errs = ev._validate_openvex_statement(0, bad)
    assert any("vulnerability.name" in e for e in errs)
    assert any("products[0].@id" in e for e in errs)
    assert any("status=" in e for e in errs)


def test_validate_openvex_statement_not_affected_bad_justification() -> None:
    bad = {
        "vulnerability": {"name": "CVE-1"},
        "products": [{"@id": "pkg:x"}],
        "status": "not_affected",
        "justification": "not_a_real_enum",
    }
    errs = ev._validate_openvex_statement(0, bad)
    assert any("justification=" in e for e in errs)


def test_validate_openvex_statement_affected_requires_action() -> None:
    bad = {
        "vulnerability": {"name": "CVE-1"},
        "products": [{"@id": "pkg:x"}],
        "status": "affected",
    }
    errs = ev._validate_openvex_statement(0, bad)
    assert any("action_statement" in e for e in errs)


def test_validate_openvex_structure_field_and_version_and_statements() -> None:
    bad = {
        "@context": ev._OPENVEX_CONTEXT,
        "@id": "",  # missing
        "author": "",  # missing
        "timestamp": "",  # missing
        "version": 2,  # wrong
        "statements": "nope",  # not a list
    }
    errs = ev._validate_openvex_structure(bad)
    assert any("@id missing" in e for e in errs)
    assert any("author missing" in e for e in errs)
    assert any("timestamp missing" in e for e in errs)
    assert any("version must be 1" in e for e in errs)
    assert any("statements[] must be an array" in e for e in errs)


# --------------------------------------------------------------------------- #
# _run_emit_vex — full flow, both formats, error paths
# --------------------------------------------------------------------------- #


def test_run_emit_vex_unknown_format(tmp_path: Path) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1")
    with pytest.raises(InvalidInputError, match="Unknown --format"):
        ev._run_emit_vex(
            sarif, None, tmp_path / "w.yaml", validate_output=False, include_references=False, output_format="csaf"
        )


def test_run_emit_vex_missing_sarif(tmp_path: Path) -> None:
    with pytest.raises(InvalidInputError, match="SARIF not found"):
        ev._run_emit_vex(
            tmp_path / "absent.json", None, tmp_path / "w.yaml", validate_output=False, include_references=False
        )


def test_run_emit_vex_bad_sarif_shape(tmp_path: Path) -> None:
    sarif = _sarif(tmp_path, {"not_runs": []})
    with pytest.raises(InvalidInputError, match="runs"):
        ev._run_emit_vex(sarif, None, tmp_path / "w.yaml", validate_output=False, include_references=False)


def test_run_emit_vex_cyclonedx_to_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1", "GHSA-2")
    ev._run_emit_vex(sarif, None, tmp_path / "absent.yaml", validate_output=True, include_references=True)
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["bomFormat"] == "CycloneDX"
    assert {v["id"] for v in doc["vulnerabilities"]} == {"CVE-1", "GHSA-2"}


def test_run_emit_vex_openvex_to_stdout_warns_placeholder(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1")
    ev._run_emit_vex(
        sarif, None, tmp_path / "absent.yaml", validate_output=True, include_references=False, output_format="openvex"
    )
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["@context"] == ev._OPENVEX_CONTEXT
    assert "product" in captured.err.lower()


def test_run_emit_vex_writes_file_and_reports_waivers(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import yaml

    sarif = _rules_sarif(tmp_path, "CVE-MATCH")
    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        yaml.safe_dump(
            {
                "waivers": [
                    {"vulnerability_ids": ["CVE-MATCH"], "justification": "j", "owner": "o"},
                    {"vulnerability_ids": ["CVE-UNMATCHED"], "justification": "j2", "owner": "o"},
                ]
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out" / "vex.json"
    ev._run_emit_vex(sarif, out, waivers, validate_output=False, include_references=False)
    assert out.is_file()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "not_affected"
    err = capsys.readouterr().err
    assert "Wrote CycloneDX VEX 1.6 document" in err
    assert "did not match any SARIF finding" in err  # CVE-UNMATCHED


def test_run_emit_vex_write_oserror(tmp_path: Path) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1")
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file", encoding="utf-8")  # parent path is a file -> mkdir fails
    out = blocker / "vex.json"
    with pytest.raises(InvalidInputError, match="Cannot write to --output"):
        ev._run_emit_vex(sarif, out, tmp_path / "absent.yaml", validate_output=False, include_references=False)


def test_run_emit_vex_openvex_validation_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1")
    monkeypatch.setattr(ev, "_validate_openvex_structure", lambda doc: ["forced openvex error"])
    with pytest.raises(InvalidInputError, match="OpenVEX structural validation failed"):
        ev._run_emit_vex(
            sarif,
            None,
            tmp_path / "absent.yaml",
            validate_output=True,
            include_references=False,
            output_format="openvex",
            product="pkg:x@1",
        )


def test_run_emit_vex_cyclonedx_validation_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1")
    monkeypatch.setattr(ev, "_validate_vex_structure", lambda doc: ["forced cdx error"])
    with pytest.raises(InvalidInputError, match="CycloneDX VEX 1.6 structural validation failed"):
        ev._run_emit_vex(sarif, None, tmp_path / "absent.yaml", validate_output=True, include_references=False)


# --------------------------------------------------------------------------- #
# emit-vex Typer command wrapper — exit codes (in-process via CliRunner)
# --------------------------------------------------------------------------- #


def test_cmd_success_stdout(tmp_path: Path) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1")
    res = runner.invoke(app, ["emit-vex", "--osv-sarif", str(sarif)])
    assert res.exit_code == 0, res.output
    assert "CycloneDX" in res.output


def test_cmd_bad_format_exit_2(tmp_path: Path) -> None:
    sarif = _rules_sarif(tmp_path, "CVE-1")
    res = runner.invoke(app, ["emit-vex", "--osv-sarif", str(sarif), "--format", "csaf"])
    assert res.exit_code == 2


def test_cmd_typer_exit_is_propagated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import typer

    def _raise_exit(*a: object, **k: object) -> None:
        raise typer.Exit(code=7)

    monkeypatch.setattr(ev, "_run_emit_vex", _raise_exit)
    sarif = _rules_sarif(tmp_path, "CVE-1")
    res = runner.invoke(app, ["emit-vex", "--osv-sarif", str(sarif)])
    assert res.exit_code == 7


def test_cmd_unexpected_error_exit_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_value(*a: object, **k: object) -> None:
        raise ValueError("kaboom")

    monkeypatch.setattr(ev, "_run_emit_vex", _raise_value)
    sarif = _rules_sarif(tmp_path, "CVE-1")
    res = runner.invoke(app, ["emit-vex", "--osv-sarif", str(sarif)])
    assert res.exit_code == 3
    assert "Unexpected error" in res.output
