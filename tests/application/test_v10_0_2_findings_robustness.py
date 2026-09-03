"""v10.0.2 robustness regressions for the correlate-findings finding pipeline.

Each test pins one confirmed defect from the extreme end-user raio-x so a future
refactor cannot silently reintroduce it. No network, no state — the pure
normalizers/report builder run directly and the CLI runs via CliRunner.

Defects covered:
- #5   deeply-nested JSON to --enrichment-file crashed correlate-findings with
       exit 3 (RecursionError). Now degrades to an "unreadable" source record.
- #6   deeply-nested kit-evidence (e.g. sast-semgrep.json) crashed with exit 3.
       Now degrades to an "unreadable" source record; the artifact still builds.
- #15  non-finite / out-of-range EPSS/CVSS in an external SARIF drop wrote
       invalid JSON (Infinity/NaN) into findings/1.0 and warped ranking. Now
       sanitized to None so the artifact stays valid JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from oss_policy_kit import __version__ as KIT_VERSION
from oss_policy_kit.application.finding_normalization import normalize_kit_evidence
from oss_policy_kit.application.finding_sarif import _safe_float, normalize_sarif_sources
from oss_policy_kit.application.findings_report import build_findings_report
from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()

_EVID = Path(".oss-policy-kit") / "evidence"
_SARIF_DIR = _EVID / "sast"

# Nesting depth far above the interpreter recursion limit (default 1000) so
# json.loads raises RecursionError, but only ~12 KB — well under MAX_EVIDENCE_BYTES
# (5 MiB), so the loader actually reaches json.loads instead of refusing as oversize.
_DEEP_JSON = "[" * 6000 + "]" * 6000


def _write(repo: Path, rel: str | Path, text: str) -> Path:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _osv_sarif(props: dict[str, Any], *, rule: str = "CVE-2026-9999") -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "osv-scanner"}},
                "results": [
                    {
                        "ruleId": rule,
                        "level": "error",
                        "message": {"text": "vuln"},
                        "properties": props,
                    }
                ],
            }
        ],
    }


def _invoke(args: list[str]):  # type: ignore[no-untyped-def]
    return runner.invoke(app, prepare_cli_args(args))


# --------------------------------------------------------------------------- #
# #5  deeply-nested --enrichment-file must not crash (exit 3 / RecursionError)
# --------------------------------------------------------------------------- #


def test_bug5_deeply_nested_enrichment_degrades_not_crashes(tmp_path: Path) -> None:
    _write(tmp_path, "enrich.json", _DEEP_JSON)
    # Must not raise RecursionError; the enrichment source is recorded unreadable.
    report = build_findings_report(
        tmp_path,
        kit_version=KIT_VERSION,
        enrichment_path=tmp_path / "enrich.json",
    )
    enrich = [s for s in report["sources_read"] if s["kind"] == "enrichment-snapshot"]
    assert enrich
    assert enrich[0]["status"] == "unreadable"


def test_bug5_deeply_nested_enrichment_cli_never_exit_3(tmp_path: Path) -> None:
    _write(tmp_path, "enrich.json", _DEEP_JSON)
    out = tmp_path / "out.json"
    result = _invoke(
        [
            "correlate-findings",
            "--target",
            str(tmp_path),
            "--enrichment-file",
            str(tmp_path / "enrich.json"),
            "-o",
            str(out),
        ]
    )
    assert result.exit_code == 0, result.output
    assert "Unexpected error" not in result.output
    assert "recursion" not in result.output.lower()
    data = json.loads(out.read_text(encoding="utf-8"))
    enrich = [s for s in data["sources_read"] if s["kind"] == "enrichment-snapshot"]
    assert enrich
    assert enrich[0]["status"] == "unreadable"


# --------------------------------------------------------------------------- #
# #6  deeply-nested kit-evidence must not crash (exit 3 / RecursionError)
# --------------------------------------------------------------------------- #


def test_bug6_deeply_nested_kit_evidence_degrades_not_crashes(tmp_path: Path) -> None:
    _write(tmp_path, _EVID / "sast-semgrep.json", _DEEP_JSON)
    findings, records = normalize_kit_evidence(tmp_path)
    semgrep = [r for r in records if r.path.endswith("sast-semgrep.json")]
    assert semgrep
    assert semgrep[0].status == "unreadable"
    # The unreadable source contributes no findings but never aborts the run.
    assert all("sast-semgrep" not in s.source_path for f in findings for s in f.sources)


def test_bug6_deeply_nested_kit_evidence_cli_never_exit_3(tmp_path: Path) -> None:
    _write(tmp_path, _EVID / "sast-semgrep.json", _DEEP_JSON)
    out = tmp_path / "out.json"
    result = _invoke(["correlate-findings", "--target", str(tmp_path), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "Unexpected error" not in result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    semgrep = [s for s in data["sources_read"] if s["path"].endswith("sast-semgrep.json")]
    assert semgrep
    assert semgrep[0]["status"] == "unreadable"


# --------------------------------------------------------------------------- #
# #15  non-finite / out-of-range EPSS/CVSS must not poison the artifact
# --------------------------------------------------------------------------- #


def test_bug15_safe_float_rejects_non_finite_and_out_of_range() -> None:
    # Non-finite (would serialize as invalid JSON Infinity/NaN).
    assert _safe_float("1e400") is None  # -> inf
    assert _safe_float("NaN") is None
    assert _safe_float("inf", lo=0.0, hi=10.0) is None
    assert _safe_float(float("-inf")) is None
    # Out of range with bounds supplied.
    assert _safe_float(999, lo=0.0, hi=1.0) is None
    assert _safe_float(-1, lo=0.0, hi=1.0) is None
    assert _safe_float(42.0, lo=0.0, hi=10.0) is None
    # Valid values still pass (no over-rejection).
    assert _safe_float("0.91", lo=0.0, hi=1.0) == 0.91
    assert _safe_float(9.8, lo=0.0, hi=10.0) == 9.8
    assert _safe_float(0.0, lo=0.0, hi=1.0) == 0.0
    assert _safe_float(None) is None


def test_bug15_non_finite_sarif_props_sanitized_to_none(tmp_path: Path) -> None:
    _write(
        tmp_path,
        _SARIF_DIR / "osv-scanner.sarif.json",
        json.dumps(_osv_sarif({"epss_score": "1e400", "cvss_score": "NaN", "cve": "CVE-2026-9999"})),
    )
    findings, _ = normalize_sarif_sources(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.epss is None
    assert f.cvss is None


def test_bug15_out_of_range_epss_cvss_sanitized_to_none(tmp_path: Path) -> None:
    _write(
        tmp_path,
        _SARIF_DIR / "osv-scanner.sarif.json",
        json.dumps(_osv_sarif({"epss_score": 999, "cvss_score": 42.0, "cve": "CVE-2026-9999"})),
    )
    findings, _ = normalize_sarif_sources(tmp_path)
    assert findings[0].epss is None
    assert findings[0].cvss is None


def test_bug15_valid_epss_cvss_still_pass_through(tmp_path: Path) -> None:
    _write(
        tmp_path,
        _SARIF_DIR / "osv-scanner.sarif.json",
        json.dumps(_osv_sarif({"epss_score": "0.91", "cvss_score": 9.8, "cve": "CVE-2026-9999"})),
    )
    findings, _ = normalize_sarif_sources(tmp_path)
    assert findings[0].epss == 0.91
    assert findings[0].cvss == 9.8


def test_bug15_artifact_is_valid_json_no_infinity_nan(tmp_path: Path) -> None:
    _write(
        tmp_path,
        _SARIF_DIR / "osv-scanner.sarif.json",
        json.dumps(_osv_sarif({"epss_score": "1e400", "cvss_score": "Infinity", "cve": "CVE-2026-9999"})),
    )
    report = build_findings_report(tmp_path, kit_version=KIT_VERSION)
    raw = json.dumps(report, sort_keys=True)
    assert "Infinity" not in raw
    assert "NaN" not in raw

    # Strict re-parse: any non-finite constant would raise here.
    def _reject(token: str) -> float:
        raise ValueError(f"non-finite constant in artifact: {token}")

    reparsed = json.loads(raw, parse_constant=_reject)
    for f in reparsed["findings"]:
        assert f["epss"] is None or math.isfinite(f["epss"])
        assert f["cvss"] is None or math.isfinite(f["cvss"])
