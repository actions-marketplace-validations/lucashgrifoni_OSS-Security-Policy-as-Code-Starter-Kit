"""UAT regressions for the ``export-vex`` bucket: fail-closed ``--report`` + VEX path hygiene.

Two confirmed defects, each reproduced before the fix:

- **export-evidence-report** (silent-wrong): a ``--report`` path that does not
  exist or is a directory was dropped from the candidate list and auto-discovery
  took over, so the tool exported ``<target>/out/evaluation-report.json`` — a
  *different* evaluation than the one the operator named — and exited 0. An
  operator attesting release evidence would ship evidence for the wrong run.
  Auto-discovery is only correct when ``--report`` was not supplied at all.
- **emit-vex-path** (leak): the ``--osv-sarif`` path was embedded verbatim into
  the CycloneDX ``analysis.detail`` and the OpenVEX ``status_notes``. A VEX
  document is published to downstream consumers, so that shipped the producer's
  absolute directory layout (and OS username) to everyone who reads the document.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.emit_vex import _build_openvex_document, _build_vex_document
from oss_policy_kit.cli.export_evidence import _load_evaluation_report
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()

_ALL_FORMATS = ("chainloop", "sarif", "spdx", "oscal", "in-toto-bundle", "gemara")

# The report auto-discovery would substitute. ``target_path`` is a sentinel so a
# rendered document can be proven to come from *this* report and not the named one.
_AUTO_REPORT = {
    "schema_version": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0",
    "contract_version": "reports/2.0",
    "target_path": "AUTO-DISCOVERED-NOT-THE-NAMED-REPORT",
    "profile": {"id": "github-level-1"},
    "summary_by_status": {"PASS": 1},
    "controls": [{"id": "GOV-SEC-001", "state": "PASS", "message": "ok"}],
}


def _plant_autodiscoverable_report(target: Path) -> None:
    out = target / "out"
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation-report.json").write_text(json.dumps(_AUTO_REPORT), encoding="utf-8")


# --------------------------------------------------------------------------- #
# export-evidence-report: an unusable --report must fail closed, never substitute
# --------------------------------------------------------------------------- #


def test_missing_report_does_not_silently_export_the_autodiscovered_one(tmp_path: Path) -> None:
    """A typo'd --report exported a different evaluation at exit 0: the operator
    signs off on evidence for a run they never named. Must exit 2 and write nothing."""
    _plant_autodiscoverable_report(tmp_path)
    out = tmp_path / "evidence.json"
    res = runner.invoke(
        app,
        [
            "export-evidence",
            "--target",
            str(tmp_path),
            "--format",
            "sarif",
            "--report",
            str(tmp_path / "typo-report.json"),
            "--output",
            str(out),
        ],
    )
    assert res.exit_code == 2, f"exit={res.exit_code}\n{res.output}"
    assert not out.exists(), "a substituted evaluation was exported for a --report that does not exist"


def test_missing_report_fails_closed_for_every_format(tmp_path: Path) -> None:
    """Every renderer honours the same fail-closed rule; none has its own fallback."""
    _plant_autodiscoverable_report(tmp_path)
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
                str(tmp_path / "typo-report.json"),
                "--output",
                str(out),
            ],
        )
        assert res.exit_code == 2, f"{fmt}: exit={res.exit_code}\n{res.output}"
        assert not out.exists(), f"{fmt}: exported a substituted evaluation"


def test_report_pointing_at_a_directory_fails_closed(tmp_path: Path) -> None:
    """``--report out`` (the directory, not the file) silently exported the
    auto-discovered report instead of refusing the unusable input."""
    _plant_autodiscoverable_report(tmp_path)
    a_dir = tmp_path / "reports-dir"
    a_dir.mkdir()
    out = tmp_path / "evidence.json"
    res = runner.invoke(
        app,
        [
            "export-evidence",
            "--target",
            str(tmp_path),
            "--format",
            "sarif",
            "--report",
            str(a_dir),
            "--output",
            str(out),
        ],
    )
    assert res.exit_code == 2, f"exit={res.exit_code}\n{res.output}"
    assert not out.exists(), "a directory --report must not fall back to auto-discovery"


def test_empty_report_is_rejected_with_an_empty_message(tmp_path: Path) -> None:
    """A truncated/zero-byte report (a half-written CI artifact) must say it is
    empty, not surface a raw json decoder position."""
    rep = tmp_path / "half-written.json"
    rep.write_text("", encoding="utf-8")
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, rep)
    assert "is empty" in ei.value.message, ei.value.message


def test_whitespace_only_report_is_rejected_as_empty(tmp_path: Path) -> None:
    """A whitespace-only report is as unusable as a zero-byte one."""
    rep = tmp_path / "blank.json"
    rep.write_text("   \n\t\n", encoding="utf-8")
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, rep)
    assert "is empty" in ei.value.message, ei.value.message


def test_load_report_raises_for_missing_explicit_report_even_with_fallbacks(tmp_path: Path) -> None:
    """Unit-level proof of the substitution: both fallback locations are usable, and
    the loader must still refuse rather than return one of them."""
    _plant_autodiscoverable_report(tmp_path)
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, tmp_path / "nope.json")
    assert "--report" in ei.value.message, ei.value.message


def test_load_report_raises_for_directory_explicit_report(tmp_path: Path) -> None:
    _plant_autodiscoverable_report(tmp_path)
    a_dir = tmp_path / "a-dir"
    a_dir.mkdir()
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, a_dir)
    assert "directory" in ei.value.message, ei.value.message


def test_non_regular_file_report_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A --report that exists but is not a regular file (a device, a socket, a symlink
    to nowhere) must refuse too — it used to be skipped, which is the substitution again."""
    _plant_autodiscoverable_report(tmp_path)
    special = tmp_path / "a-device"
    special.write_text("{}", encoding="utf-8")
    real_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self, *a, **k: False if self == special else real_is_file(self, *a, **k),
    )
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, special)
    assert "not a regular file" in ei.value.message, ei.value.message


def test_explicit_report_errors_never_leak_the_absolute_path(tmp_path: Path) -> None:
    """M-002: the refusal names the basename the operator typed, never the resolved
    path (which carries cwd/home/OS username into a shared terminal or CI log)."""
    a_dir = tmp_path / "a-dir"
    a_dir.mkdir()
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    for candidate in (tmp_path / "nope.json", a_dir, empty):
        with pytest.raises(InvalidInputError) as ei:
            _load_evaluation_report(tmp_path, candidate)
        assert str(tmp_path) not in ei.value.message, ei.value.message


def test_utf16_report_exits_2_without_leaking_the_absolute_path(tmp_path: Path) -> None:
    """Windows PowerShell ``>`` writes UTF-16, so an operator's own report can be
    UTF-16: it must be named as such (exit 2, no traceback) without echoing the path."""
    rep = tmp_path / "utf16-report.json"
    rep.write_text(json.dumps(_AUTO_REPORT), encoding="utf-16")
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, rep)
    assert "UTF-8" in ei.value.message, ei.value.message
    assert str(tmp_path) not in ei.value.message, ei.value.message
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--report", str(rep)])
    assert res.exit_code == 2, res.output
    assert "Unexpected error" not in res.output, res.output


def test_unreadable_report_message_uses_strerror_not_the_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """M-002: ``str(OSError)`` embeds the offending absolute path, so a permission
    error on the report would have printed the auditor's home directory."""
    rep = tmp_path / "locked.json"
    rep.write_text(json.dumps(_AUTO_REPORT), encoding="utf-8")

    def _boom(self: Path, *args: object, **kwargs: object) -> str:
        raise PermissionError(13, "Permission denied", str(rep))

    monkeypatch.setattr(Path, "read_text", _boom)
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, rep)
    assert "Permission denied" in ei.value.message, ei.value.message
    assert str(tmp_path) not in ei.value.message, ei.value.message


def test_autodiscovered_report_parse_failure_does_not_leak_the_absolute_path(tmp_path: Path) -> None:
    """M-002: the auto-discovery path echoed the *resolved* candidate, so a malformed
    ``out/evaluation-report.json`` printed the auditor's home directory."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "evaluation-report.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, None)
    assert "evaluation-report.json" in ei.value.message, ei.value.message
    assert str(tmp_path) not in ei.value.message, ei.value.message


def test_no_report_found_message_does_not_leak_the_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M-002: the "locations tried" hint listed two resolved absolute paths."""
    # cwd is one of the auto-discovery roots; move off the repo (which has its own
    # out/evaluation-report.json) so the not-found branch is the one under test.
    empty_cwd = tmp_path / "empty-cwd"
    empty_cwd.mkdir()
    monkeypatch.chdir(empty_cwd)
    with pytest.raises(InvalidInputError) as ei:
        _load_evaluation_report(tmp_path, None)
    assert str(tmp_path) not in ei.value.message, ei.value.message


# --- the fix must not disable auto-discovery when --report was NOT supplied ---


def test_autodiscovery_still_works_when_report_flag_is_omitted(tmp_path: Path) -> None:
    """Guard against over-correcting: omitting --report must still find
    ``<target>/out/evaluation-report.json``."""
    _plant_autodiscoverable_report(tmp_path)
    out = tmp_path / "evidence.json"
    res = runner.invoke(app, ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--output", str(out)])
    assert res.exit_code == 0, res.output
    assert out.is_file()


def test_explicit_report_still_wins_over_autodiscovery_when_usable(tmp_path: Path) -> None:
    """A usable --report is used, and the auto-discoverable report is ignored."""
    _plant_autodiscoverable_report(tmp_path)
    named = dict(_AUTO_REPORT, target_path="THE-NAMED-REPORT")
    rep = tmp_path / "named.json"
    rep.write_text(json.dumps(named), encoding="utf-8")
    out = tmp_path / "evidence.json"
    res = runner.invoke(
        app,
        [
            "export-evidence",
            "--target",
            str(tmp_path),
            "--format",
            "in-toto-bundle",
            "--report",
            str(rep),
            "--output",
            str(out),
        ],
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["subject"][0]["name"] == "THE-NAMED-REPORT"


# --------------------------------------------------------------------------- #
# emit-vex-path: the published VEX must not carry the producer's directory layout
# --------------------------------------------------------------------------- #

_SARIF_DOC = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "osv-scanner", "rules": [{"id": "CVE-2024-0001"}]}},
            "results": [{"ruleId": "CVE-2024-0001"}],
        }
    ],
}


def test_cyclonedx_detail_names_the_sarif_basename_only(tmp_path: Path) -> None:
    """The CycloneDX analysis.detail is published to downstream consumers; it must
    identify the evidence file without mapping the producer's filesystem."""
    source = tmp_path / "evidence" / "sast" / "osv-scanner.sarif.json"
    doc = _build_vex_document(["CVE-2024-0001"], source)
    detail = doc["vulnerabilities"][0]["analysis"]["detail"]
    assert "osv-scanner.sarif.json" in detail
    # Separator-free needles: "evidence/sast" cannot match a Windows-shaped leak.
    assert "evidence" not in detail, detail
    assert "sast" not in detail, detail
    assert str(tmp_path) not in detail, detail
    assert tmp_path.as_posix() not in detail, detail


def test_openvex_status_notes_names_the_sarif_basename_only(tmp_path: Path) -> None:
    """Same leak on the OpenVEX side (status_notes)."""
    source = tmp_path / "evidence" / "sast" / "osv-scanner.sarif.json"
    doc = _build_openvex_document(["CVE-2024-0001"], source, product="pkg:pypi/acme@1.2.3")
    notes = doc["statements"][0]["status_notes"]
    assert "osv-scanner.sarif.json" in notes
    # Separator-free needles: "evidence/sast" cannot match a Windows-shaped leak.
    assert "evidence" not in notes, notes
    assert "sast" not in notes, notes
    assert str(tmp_path) not in notes, notes
    assert tmp_path.as_posix() not in notes, notes


@pytest.mark.parametrize("fmt", ["cyclonedx", "openvex"])
def test_emitted_vex_document_carries_no_directory_component(tmp_path: Path, fmt: str) -> None:
    """End-to-end: running with an absolute --osv-sarif must not write the producer's
    directory layout into the document that gets shared."""
    sarif = tmp_path / "nested" / "osv.sarif.json"
    sarif.parent.mkdir(parents=True)
    sarif.write_text(json.dumps(_SARIF_DOC), encoding="utf-8")
    out = tmp_path / "vex.json"
    args = [
        "emit-vex",
        "--osv-sarif",
        str(sarif),
        "--waivers",
        str(tmp_path / "absent-waivers.yaml"),
        "--output",
        str(out),
        "--format",
        fmt,
    ]
    if fmt == "openvex":
        args += ["--product", "pkg:pypi/acme@1.2.3"]
    res = runner.invoke(app, args)
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    cited = (
        doc["vulnerabilities"][0]["analysis"]["detail"] if fmt == "cyclonedx" else doc["statements"][0]["status_notes"]
    )
    assert "osv.sarif.json" in cited, cited
    # Asserted on the DECODED value, not the raw file text: json.dumps doubles Windows
    # separators, so a leak written as C:\...\nested\osv.sarif.json could never match a
    # POSIX-shaped needle -- the guard had no force on the platform it was written on.
    # parent.name carries no separator at all, so it catches a leak on either platform.
    assert sarif.parent.name not in cited, cited
    assert str(sarif.parent) not in cited, cited
    assert sarif.parent.as_posix() not in cited, cited
