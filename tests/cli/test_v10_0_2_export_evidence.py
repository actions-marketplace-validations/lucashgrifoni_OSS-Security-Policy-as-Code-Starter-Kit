"""v10.0.2 hotfix regressions for ``export-evidence`` (raio-x, group export-evidence).

Four confirmed defects, each with at least one test that fails before the fix:

- #10/#12 non-determinism: every embedded ``created``/``annotationDate``/
  ``evaluatedAt``/``date`` timestamp went through ``datetime.now(UTC)``, ignoring
  ``SOURCE_DATE_EPOCH``. They now route through the SDE-honoring clock, so a
  re-generated artifact is byte-identical and carries the pinned epoch.
- #18 non-determinism: ``--format oscal`` minted fresh ``uuid4()`` per run, so the
  bundle differed every time even under a frozen clock. The OSCAL ids are now
  derived deterministically (uuid5 over stable content + the pinned timestamp).
- #11 silent-wrong: a JSON *object* that is not a reports/2.0 report slipped past
  the ``isinstance(dict)`` gate and rendered a misleading empty attestation at
  exit 0. It is now rejected with a clean exit 2 (M-002-safe message).
- M-002: a bad ``--target`` echoed ``target.resolve()``, leaking the auditor's
  cwd/home/username. It now echoes the user-supplied string.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.export_evidence import (
    _is_reports_v2,
    _load_evaluation_report,
    _now_iso8601_z,
    _render_gemara,
    _render_oscal,
    _render_spdx,
    _run_export_evidence,
    _validate,
)
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()

# conftest pins SOURCE_DATE_EPOCH=1781524800 == 2026-06-15T12:00:00Z for the whole suite.
_PINNED_Z = "2026-06-15T12:00:00Z"

_REPORT_2_0 = {
    "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0",
    "contract_version": "reports/2.0",
    "target_path": "examples/hardened-repo",
    "profile": {"id": "github-level-1"},
    "summary_by_status": {"PASS": 1, "FAIL": 1},
    "controls": [
        {"id": "GOV-SEC-001", "state": "PASS", "message": "ok", "assurance": "deterministic"},
        {"id": "CI-PIN-008", "state": "FAIL", "message": "mutable refs"},
    ],
}


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


# --- #10 / #12: timestamps honour SOURCE_DATE_EPOCH -------------------------


def test_now_iso8601_z_honours_source_date_epoch() -> None:
    """The clock returns the pinned epoch (not wall-clock); fails before the fix."""
    assert _now_iso8601_z() == _PINNED_Z


def test_now_iso8601_z_tracks_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Changing SOURCE_DATE_EPOCH changes the stamp — proves the env is honoured,
    not a hard-coded constant."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    assert _now_iso8601_z() == "1970-01-01T00:00:00Z"


def test_spdx_and_gemara_timestamps_are_pinned() -> None:
    spdx = _render_spdx(_REPORT_2_0)
    assert spdx["creationInfo"]["created"] == _PINNED_Z
    assert spdx["packages"][0]["annotations"][0]["annotationDate"] == _PINNED_Z
    gemara = _render_gemara(_REPORT_2_0)
    assert gemara["metadata"]["date"] == _PINNED_Z


def test_spdx_render_is_byte_identical_across_runs() -> None:
    a = json.dumps(_render_spdx(_REPORT_2_0), indent=2, sort_keys=True)
    b = json.dumps(_render_spdx(_REPORT_2_0), indent=2, sort_keys=True)
    assert a == b


# --- #18: oscal uuids are deterministic ------------------------------------


def test_oscal_render_is_byte_identical_across_runs() -> None:
    """Two renders under the frozen clock are byte-identical; fails before the fix
    (uuid4 minted fresh ids every run)."""
    a = json.dumps(_render_oscal(_REPORT_2_0), sort_keys=True)
    b = json.dumps(_render_oscal(_REPORT_2_0), sort_keys=True)
    assert a == b


def test_oscal_uuids_are_deterministic_unique_and_uuid5() -> None:
    doc = _render_oscal(_REPORT_2_0)
    ar = doc["assessment-results"]
    result = ar["results"][0]
    collected = [
        ar["uuid"],
        result["uuid"],
        result["assessment-log"]["entries"][0]["uuid"],
        *[o["uuid"] for o in result["observations"]],
    ]
    # all distinct within the document (OSCAL requires unique uuids)
    assert len(collected) == len(set(collected))
    # derived (uuid5), not random (uuid4)
    for u in collected:
        assert uuid.UUID(u).version == 5
    # the subject the observations point at is also stable + shared
    subj = result["observations"][0]["subjects"][0]["subject-uuid"]
    assert uuid.UUID(subj).version == 5
    assert result["assessment-subjects"][0]["include-subjects"][0]["subject-uuid"] == subj
    # still structurally valid
    assert _validate(doc, "oscal") == []


def test_oscal_uuids_track_the_pinned_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A different pinned epoch yields a different (still deterministic) bundle —
    proves the epoch is folded into the derivation, not ignored."""
    base = json.dumps(_render_oscal(_REPORT_2_0), sort_keys=True)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    other = json.dumps(_render_oscal(_REPORT_2_0), sort_keys=True)
    assert base != other


# --- #11: a non-report object is rejected (not a misleading empty export) ---


def test_is_reports_v2_predicate() -> None:
    assert _is_reports_v2(_REPORT_2_0) is True
    # marker via schema_version only (no contract_version) still counts
    assert _is_reports_v2({"schema_version": "https://example/reports/2.0", "controls": []}) is True
    # not a report: no marker and/or no controls list
    assert _is_reports_v2({"foo": "bar"}) is False
    assert _is_reports_v2({"summary_by_status": {}}) is False
    # marker but no controls list -> still not a usable report (would render empty)
    assert _is_reports_v2({"contract_version": "reports/2.0"}) is False


def test_load_evaluation_report_rejects_non_report_object(tmp_path: Path) -> None:
    rep = tmp_path / "notreport.json"
    _write(rep, {"foo": "bar", "hello": "world"})
    with pytest.raises(InvalidInputError, match="not a reports/2.0 report"):
        _load_evaluation_report(tmp_path, rep)


def test_load_evaluation_report_still_accepts_real_report(tmp_path: Path) -> None:
    rep = tmp_path / "report.json"
    _write(rep, _REPORT_2_0)
    data = _load_evaluation_report(tmp_path, rep)
    assert data["target_path"] == "examples/hardened-repo"


def test_cli_non_report_object_rejected_exit_2_no_file(tmp_path: Path) -> None:
    """All 6 formats: a non-report object exits 2, writes no evidence file, and the
    message names the report basename only (never the absolute path — M-002)."""
    rep = tmp_path / "config.json"
    _write(rep, {"foo": "bar"})
    for fmt in ("chainloop", "sarif", "spdx", "oscal", "in-toto-bundle", "gemara"):
        out = tmp_path / f"ev-{fmt}.json"
        res = runner.invoke(
            app,
            ["export-evidence", "--target", str(tmp_path), "--format", fmt, "--report", str(rep), "--output", str(out)],
        )
        assert res.exit_code == 2, f"{fmt}: {res.exit_code}\n{res.output}"
        assert not out.exists(), f"{fmt}: no evidence file must be written for a non-report"
        assert "config.json" in res.output, f"{fmt}: message must name the report basename\n{res.output}"
        assert str(tmp_path) not in res.output, f"{fmt}: absolute path leaked\n{res.output}"


# --- M-002: bad --target echoes the user string, not the resolved abs path --


def test_bad_target_message_echoes_user_string_not_resolved_path(tmp_path: Path) -> None:
    """Wrap-immune unit check: a relative, non-existent --target produces a message
    that echoes exactly what the user typed and never the resolved absolute path
    (which would leak cwd/home/username). Fails before the fix."""
    rel = Path("definitely-not-a-dir-xyz")
    resolved = str(rel.resolve())
    with pytest.raises(InvalidInputError) as ei:
        _run_export_evidence(rel, "sarif", tmp_path / "o.json", None, False)
    msg = ei.value.message
    assert msg == "--target definitely-not-a-dir-xyz is not a directory."
    assert resolved not in msg
