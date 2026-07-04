"""v10.0.1 hotfix regressions for ``export-evidence`` (unit F3).

Covers three confirmed defects:

- X5-01 / X8-1 / X5-02: ``export-evidence`` silently accepted a stored pre-2.0
  report (data under ``results``, no ``controls`` key), emitting all-unknown /
  content-dropped evidence with exit 0, while item 4 of the v10.0.0 migration
  guide promises "requires reports/2.0 input". A legacy report must now fail
  fast (exit 2, clean message, migration pointer) BEFORE any renderer runs and
  regardless of ``--validate`` — which also makes the misleading "no controls to
  export" message unreachable for legacy input (X5-02).
- X8-3: docs document ``-t``/``-o`` aliases the command lacked.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()

_ALL_FORMATS = ("chainloop", "sarif", "spdx", "oscal", "in-toto-bundle", "gemara")

# A stored reports/1.0 report: schema_version names the removed contract, data lives
# under ``results`` (1.0 shape), and there is no ``controls`` key.
_LEGACY_1_0 = {
    "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/1.0",
    "target": "C:/tmp/repo",
    "profile": {"id": "github-level-1"},
    "summary_by_status": {"pass": 2, "fail": 1},
    "results": [
        {"id": "GOV-SEC-001", "status": "pass", "reason": "ok"},
        {"id": "CI-PIN-008", "status": "fail", "reason": "mutable refs"},
    ],
    "waivers": [],
}

# A real reports/2.0 report (the only contract): schema_version ends /reports/2.0,
# controls carry ``state``/``message``, target under ``target_path``.
_REPORT_2_0 = {
    "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0",
    "contract_version": "reports/2.0",
    "target_path": "examples/hardened-repo",
    "profile": {"id": "github-level-1"},
    "summary_by_status": {"PASS": 1, "FAIL": 1},
    "controls": [
        {"id": "GOV-SEC-001", "state": "PASS", "message": "SECURITY.md present."},
        {"id": "CI-PIN-008", "state": "FAIL", "message": "mutable action refs."},
    ],
}


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


# --- X5-01 / X8-1 / X5-02: legacy reports/1.0 rejected -----------------------


def test_legacy_1_0_rejected_default_path_all_formats(tmp_path: Path) -> None:
    """Default path (no --validate): a reports/1.0 report exits 2 with the migration
    pointer (NOT "no controls"), for all 6 formats, and no evidence file is written."""
    rep = tmp_path / "legacy-1.0.json"
    _write(rep, _LEGACY_1_0)
    for fmt in _ALL_FORMATS:
        out = tmp_path / f"ev-{fmt}.json"
        res = runner.invoke(
            app,
            ["export-evidence", "--target", str(tmp_path), "--format", fmt, "--report", str(rep), "--output", str(out)],
        )
        assert res.exit_code == 2, f"{fmt}: {res.exit_code}\n{res.output}"
        assert "reports/1.0" in res.output, f"{fmt}: message must name the removed contract\n{res.output}"
        assert "v10.0.0-migration-guide.md" in res.output, f"{fmt}: must point at the migration guide\n{res.output}"
        assert "no controls to export" not in res.output, f"{fmt}: legacy input must not reach the no-controls path"
        assert not out.exists(), f"{fmt}: no evidence file must be written for a rejected legacy report"


def test_legacy_1_0_rejected_with_validate_all_formats(tmp_path: Path) -> None:
    """--validate: same rejection (exit 2, migration pointer, not "no controls") —
    the guard is NOT gated behind --validate."""
    rep = tmp_path / "legacy-1.0.json"
    _write(rep, _LEGACY_1_0)
    for fmt in _ALL_FORMATS:
        out = tmp_path / f"ev-{fmt}.json"
        res = runner.invoke(
            app,
            [
                "export-evidence",
                "--target",
                str(tmp_path),
                "--format",
                fmt,
                "--report",
                str(rep),
                "--output",
                str(out),
                "--validate",
            ],
        )
        assert res.exit_code == 2, f"{fmt}: {res.exit_code}\n{res.output}"
        assert "reports/1.0" in res.output, f"{fmt}\n{res.output}"
        assert "v10.0.0-migration-guide.md" in res.output, f"{fmt}\n{res.output}"
        assert "no controls to export" not in res.output, f"{fmt}: must reject on contract, not on 0 controls"


def test_legacy_shape_without_controls_rejected(tmp_path: Path) -> None:
    """Second detection signal: a payload lacking a ``controls`` list while carrying a
    legacy ``results`` list is rejected even when schema_version does not name a
    removed contract."""
    payload = {
        "schema_version": "https://example/reports/unknown",
        "results": [{"id": "X", "status": "pass"}],
    }
    rep = tmp_path / "shape.json"
    _write(rep, payload)
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--report", str(rep)])
    assert res.exit_code == 2, res.output
    assert "v10.0.0-migration-guide.md" in res.output, res.output


def test_legacy_rejection_message_leaks_no_absolute_path(tmp_path: Path) -> None:
    """M-002 privacy: the rejection message names the report basename only, never the
    absolute path / username."""
    rep = tmp_path / "legacy-1.0.json"
    _write(rep, _LEGACY_1_0)
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--report", str(rep)])
    assert res.exit_code == 2, res.output
    assert "legacy-1.0.json" in res.output
    assert str(tmp_path) not in res.output, f"absolute path leaked:\n{res.output}"


# --- A real reports/2.0 report still exports for all 6 formats ----------------


def test_reports_2_0_still_exports_all_formats(tmp_path: Path) -> None:
    rep = tmp_path / "report-2.0.json"
    _write(rep, _REPORT_2_0)
    for fmt in _ALL_FORMATS:
        out = tmp_path / f"ev-{fmt}.json"
        res = runner.invoke(
            app,
            ["export-evidence", "--target", str(tmp_path), "--format", fmt, "--report", str(rep), "--output", str(out)],
        )
        assert res.exit_code == 0, f"{fmt}: {res.exit_code}\n{res.output}"
        assert out.is_file(), f"{fmt}: evidence file must be written"
        json.loads(out.read_text(encoding="utf-8"))  # valid JSON


def test_reports_2_0_exports_with_validate(tmp_path: Path) -> None:
    rep = tmp_path / "report-2.0.json"
    _write(rep, _REPORT_2_0)
    for fmt in _ALL_FORMATS:
        out = tmp_path / f"ev-{fmt}.json"
        res = runner.invoke(
            app,
            [
                "export-evidence",
                "--target",
                str(tmp_path),
                "--format",
                fmt,
                "--report",
                str(rep),
                "--output",
                str(out),
                "--validate",
            ],
        )
        assert res.exit_code == 0, f"{fmt}: {res.exit_code}\n{res.output}"


# --- X8-3: -t / -o short aliases ---------------------------------------------


def test_short_aliases_t_and_o(tmp_path: Path) -> None:
    rep = tmp_path / "report-2.0.json"
    _write(rep, _REPORT_2_0)
    out = tmp_path / "x.json"
    # -t for --target, -o for --output (mirrors correlate-findings / emit-vex).
    res = runner.invoke(
        app, ["export-evidence", "-t", str(tmp_path), "-o", str(out), "--format", "spdx", "--report", str(rep)]
    )
    assert res.exit_code == 0, res.output
    assert out.is_file()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["spdxVersion"] == "SPDX-2.3"
