"""Regression: v10.0.1 shareable-artifact path/username leaks (M-002 residual).

Three confirmed leaks are covered here. The invariant in every case: a report that
ships in a PR artifact, GitHub Release, or vulnerability write-up must not leak the
auditor's home directory / OS username by default, and must exactly match the JSON
report's redaction. The ``--include-absolute-path`` opt-in must restore full paths in
*every* surface it governs.

- X4-01 + X6-01 (reporting.write_markdown_report): the per-control "Evidence" bullets
  emitted ``r.evidence_sources`` RAW while the JSON report redacts the same values via
  ``project_evidence`` -> ``classify_reference`` -> ``<redacted-absolute>/...``. The
  Markdown bullets must now route through that same redaction, gated by
  ``include_absolute_path``.
- X4-03 (cli_output.print_stdout_summary): the ``json`` stdout payload emitted
  ``report.target_path`` (engine-resolved absolute) RAW instead of routing through
  ``_sanitize_target_path_for_payload`` like the report writers. It must sanitize by
  default and honor ``include_absolute_path``.
- X7-01 (batch_evaluate.run_batch_evaluation): the consolidated ``evaluation-batch.json``
  / ``.md`` serialized raw resolved absolute paths (``target_root``, ``runs[].target_path``,
  report artifact paths, ``skipped_directories[].path``). Every emitted path must be
  basename-sanitized by default and restorable via the opt-in flag threaded from
  ``evaluate-many``.

Synthetic absolute roots (never a real ``/home`` or user path) let the assertions prove
the absolute prefix, parent dirs, and username segment are stripped.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.conftest import EXAMPLE_VULNERABLE

from oss_policy_kit.application import cli_output as co
from oss_policy_kit.application import reporting as rp
from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

# Synthetic POSIX absolute root with a fake user segment + parent dirs to be stripped.
_ABS_ROOT = "/synthetic-abs-root/ci-user/secret-repo"
_ABS_EVIDENCE = _ABS_ROOT + "/.github/workflows/ci.yml"
_USERNAME = "ci-user"

# Synthetic Windows drive-rooted evidence path (a stand-in for the real-world
# home-directory leak, kept off the literal user-profile prefix so the public-hygiene
# scanner does not flag the test itself). ``_redact_path`` treats any drive-letter path
# identically, so this proves the same scrub to a bare basename in the Markdown report.
_WIN_DRIVE_PREFIX = "Z:\\synthetic-win"
_WIN_EVIDENCE = _WIN_DRIVE_PREFIX + "\\ci-user\\secret-repo\\SECURITY.md"


def _report(*, evidence: list[str]) -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-07-03T00:00:00Z",
        kit_version="10.0.1",
        target_path=_ABS_ROOT,
        profile_id="github-level-1",
        profile_title="Title",
        summary_by_status={"pass": 1},
        results=[
            ControlResult(
                control_id="GOV-SEC-001",
                title="Security policy present",
                category="governance",
                status=ControlStatus.PASS,
                profile="github-level-1",
                evidence_sources=list(evidence),
                confidence="high",
                reason="ok",
                remediation="keep",
            ),
        ],
        operational_warnings=[],
    )


# ---------------------------------------------------------------------------
# X4-01 + X6-01: markdown evidence bullets must match the JSON redaction
# ---------------------------------------------------------------------------


def test_markdown_evidence_bullets_redact_absolute_paths_by_default(tmp_path: Path) -> None:
    """Default Markdown must not leak abs-path evidence, and must match the JSON redaction."""

    report = _report(evidence=[_ABS_EVIDENCE, _WIN_EVIDENCE])

    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(report, md)
    text = md.read_text(encoding="utf-8")

    # Isolate the per-control "Detail" section (where the evidence bullets live) so the
    # target-basename line above it (a legitimate `secret-repo` basename, not a leak)
    # does not mask an actual evidence-bullet leak.
    detail = text.split("## Detail", 1)[1]

    # No username / absolute prefix / parent chain leaks into the evidence bullets.
    assert _USERNAME not in detail, "OS username segment leaked into Markdown evidence bullet"
    assert "/synthetic-abs-root/" not in detail
    assert _WIN_DRIVE_PREFIX not in detail
    # The full parent chain (basename followed by a separator) must never survive.
    assert "secret-repo/" not in detail and "secret-repo\\" not in detail

    # The Markdown evidence bullet must render the SAME value the JSON report emits.
    json_payload = rp.report_to_dict(report)
    json_refs = json_payload["controls"][0]["evidence"]["references"]
    assert json_refs, "fixture should yield at least one projected evidence reference"
    for ref in json_refs:
        assert ref["value"] in detail, "Markdown evidence bullet diverged from JSON redaction"
    # The redacted marker itself must be present (proves redaction happened, not passthrough).
    assert "<redacted-absolute>" in detail


def test_markdown_evidence_bullets_preserve_absolute_paths_with_flag(tmp_path: Path) -> None:
    """``include_absolute_path=True`` keeps the full evidence path in the Markdown (parity with JSON)."""

    report = _report(evidence=[_ABS_EVIDENCE, _WIN_EVIDENCE])

    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(report, md, include_absolute_path=True)
    text = md.read_text(encoding="utf-8")

    assert _ABS_EVIDENCE in text
    assert _WIN_EVIDENCE in text
    assert "<redacted-absolute>" not in text


# ---------------------------------------------------------------------------
# X4-03: print_stdout_summary json target_path must be sanitized by default
# ---------------------------------------------------------------------------


def test_stdout_json_summary_sanitizes_target_path_by_default(capsys) -> None:
    report = _report(evidence=[])

    co.print_stdout_summary(report, output_format="json")
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["target_path"] == "secret-repo"
    assert _USERNAME not in out
    assert "/synthetic-abs-root/" not in out


def test_stdout_json_summary_preserves_target_path_with_flag(capsys) -> None:
    report = _report(evidence=[])

    co.print_stdout_summary(report, output_format="json", include_absolute_path=True)
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert payload["target_path"] == _ABS_ROOT


# ---------------------------------------------------------------------------
# X7-01: batch artifacts must not leak absolute paths / username by default
# ---------------------------------------------------------------------------


def _run_batch(tmp_path: Path, *, include_absolute_path: bool) -> tuple[dict, str, str]:
    """Run a real batch under a sentinel-named parent; return (json_payload, json_text, md_text)."""

    # The target root sits under a synthetic sentinel directory. That sentinel is a PARENT
    # of the resolved target-root path, so if any absolute path leaks, the sentinel appears.
    parent = tmp_path / "SECRET-PARENT-DIR"
    mono = parent / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "svc-app")
    out = tmp_path / "out"

    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        include_absolute_path=include_absolute_path,
    )
    json_text = (out / "evaluation-batch.json").read_text(encoding="utf-8")
    md_text = (out / "evaluation-batch.md").read_text(encoding="utf-8")
    return json.loads(json_text), json_text, md_text


def test_batch_json_and_md_sanitize_paths_by_default(tmp_path: Path) -> None:
    payload, json_text, md_text = _run_batch(tmp_path, include_absolute_path=False)

    # target_root sanitized to basename.
    assert payload["target_root"] == "mono"
    # Per-run target_path + report artifact paths sanitized to basenames.
    run = payload["runs"][0]
    assert run["target_path"] == "svc-app"
    assert run["reports"]["json"] == "evaluation-report.json"
    assert run["reports"]["markdown"] == "evaluation-report.md"

    # The sentinel parent directory must appear in NO shareable batch artifact.
    for blob in (json_text, md_text):
        assert "SECRET-PARENT-DIR" not in blob, "absolute parent directory leaked into batch artifact"

    # Batch Markdown "Target root" line is the basename, not the abs path.
    assert "- **Target root**: `mono`" in md_text


def test_batch_skipped_directory_path_sanitized_by_default(tmp_path: Path) -> None:
    """``skipped_directories[].path`` must be a basename by default (no parent-dir leak)."""

    parent = tmp_path / "SECRET-PARENT-DIR"
    mono = parent / "mono"
    shutil.copytree(EXAMPLE_VULNERABLE, mono / "svc-app")
    # A child with no repository signals -> skipped when --skip-non-repos is set.
    (mono / "just-docs").mkdir()
    (mono / "just-docs" / "README.md").write_text("# docs only\n", encoding="utf-8")
    out = tmp_path / "out"

    run_batch_evaluation(
        target_root=mono,
        profile_ids=["github-level-1"],
        output_dir=out,
        kit_root=None,
        include=None,
        exclude=None,
        skip_non_repos=True,
    )
    json_text = (out / "evaluation-batch.json").read_text(encoding="utf-8")
    payload = json.loads(json_text)

    skipped = payload.get("skipped_directories", [])
    assert skipped, "expected the docs-only child to be skipped"
    assert skipped[0]["path"] == "just-docs"
    assert "SECRET-PARENT-DIR" not in json_text


def test_batch_include_absolute_path_restores_full_paths(tmp_path: Path) -> None:
    payload, json_text, _md_text = _run_batch(tmp_path, include_absolute_path=True)

    # With the opt-in flag, the resolved absolute paths (incl. the sentinel parent) survive.
    assert "SECRET-PARENT-DIR" in json_text
    assert payload["target_root"].endswith("mono")
    assert Path(payload["target_root"]).is_absolute()
    run = payload["runs"][0]
    assert Path(run["target_path"]).is_absolute()
    assert run["target_path"].endswith("svc-app")
