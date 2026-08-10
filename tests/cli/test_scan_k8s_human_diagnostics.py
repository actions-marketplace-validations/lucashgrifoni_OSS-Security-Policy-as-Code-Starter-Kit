"""What `scan-k8s` tells the operator on stderr when part of the scan did not happen.

The one-line summary on stdout is a machine-facing count. The warnings beside it on stderr
are what stop a partial scan from reading as a complete one: charts that could not be
rendered, templates skipped because they still hold `{{ ... }}` markers, files that failed
to parse, and `--helm-render` asked for on a machine with no `helm` binary.

Every one of those is a case where the tool looked at less than the operator thinks it did.
None of the warnings had been executed.

They go to stderr on purpose, so `scan-k8s --format json > out.json` stays parseable while
the operator still sees what was missed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.cli import scan_k8s as sk
from oss_policy_kit.infrastructure.k8s.scanner import K8sScanOutcome


def _outcome(**over: Any) -> K8sScanOutcome:
    base: dict[str, Any] = {
        "status": "ok",
        "tool_version": "10.0.10",
        "files_scanned": ["deploy.yaml"],
        "helm_templates_skipped": [],
        "parse_errors": [],
        "findings": [],
        "scanned_at": "2026-06-15T12:00:00Z",
        "diagnostics": "",
        "helm_render_attempted": False,
        "helm_available": False,
        "helm_version": None,
        "helm_charts_discovered": [],
        "helm_charts_rendered": [],
        "helm_render_errors": [],
    }
    base.update(over)
    return K8sScanOutcome(**base)


def _emit(outcome: K8sScanOutcome, capsys: pytest.CaptureFixture[str]) -> tuple[str, str]:
    sk._emit_scan_k8s_human(outcome, Path("evidence/k8s-baseline.json"))
    captured = capsys.readouterr()
    return captured.out, captured.err


# --------------------------------------------------------------------------- #
# the summary line
# --------------------------------------------------------------------------- #


def test_the_summary_reports_the_counts_and_where_the_evidence_went(
    capsys: pytest.CaptureFixture[str],
) -> None:
    out, _err = _emit(_outcome(files_scanned=["a.yaml", "b.yaml"]), capsys)

    assert "files=2" in out
    assert "k8s-baseline.json" in out


def test_a_clean_scan_warns_about_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    """The warnings below only mean something if silence is the normal case."""

    _out, err = _emit(_outcome(), capsys)

    assert err.strip() == ""


# --------------------------------------------------------------------------- #
# helm was requested but is not installed
# --------------------------------------------------------------------------- #


def test_helm_render_requested_without_helm_installed_says_so(capsys: pytest.CaptureFixture[str]) -> None:
    """The scan still runs, so without this the operator would think charts were covered."""

    _out, err = _emit(_outcome(helm_render_attempted=True, helm_available=False), capsys)

    assert "helm" in err.lower()
    assert "not on PATH" in err
    assert "scan continued" in err


def test_helm_absence_is_only_mentioned_when_rendering_was_asked_for(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Most scans never want Helm; warning about a missing tool nobody asked for is noise."""

    _out, err = _emit(_outcome(helm_render_attempted=False, helm_available=False), capsys)

    assert "PATH" not in err


# --------------------------------------------------------------------------- #
# charts that did not render
# --------------------------------------------------------------------------- #


def test_charts_that_failed_to_render_are_counted_and_pointed_at_the_evidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    outcome = _outcome(
        helm_render_attempted=True,
        helm_available=True,
        helm_render_errors=[{"chart": "web", "error": "template: parse failed"}],
    )

    _out, err = _emit(outcome, capsys)

    assert "1 chart(s) failed to render" in err
    assert "helm_render_errors" in err


def test_charts_that_rendered_are_reported_too(capsys: pytest.CaptureFixture[str]) -> None:
    """The positive note matters: it tells the operator the pre-pass actually did work."""

    outcome = _outcome(
        helm_render_attempted=True,
        helm_available=True,
        helm_charts_rendered=["web", "api"],
    )

    _out, err = _emit(outcome, capsys)

    assert "Rendered 2 Helm chart(s)" in err


def test_render_results_are_silent_when_rendering_was_never_attempted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    outcome = _outcome(helm_render_attempted=False, helm_charts_rendered=["web"], helm_render_errors=[{"a": "b"}])

    _out, err = _emit(outcome, capsys)

    assert "Rendered" not in err
    assert "failed to render" not in err


# --------------------------------------------------------------------------- #
# templates and files the scanner could not read
# --------------------------------------------------------------------------- #


def test_skipped_helm_templates_name_the_flag_that_would_include_them(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A skipped template is unscanned surface; the warning has to say how to fix it."""

    _out, err = _emit(_outcome(helm_templates_skipped=["chart/templates/deploy.yaml"]), capsys)

    assert "1 Helm template(s) skipped" in err
    assert "--helm-render" in err


def test_files_that_failed_to_parse_are_counted_and_pointed_at_the_evidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unparseable manifest is not a clean manifest, and the count must not be silent."""

    outcome = _outcome(parse_errors=[{"file": "broken.yaml", "error": "could not find expected ':'"}])

    _out, err = _emit(outcome, capsys)

    assert "1 file(s) failed to parse" in err
    assert "parse_errors" in err


def test_several_kinds_of_incompleteness_are_all_reported_together(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One warning must not suppress another; each describes different unscanned surface."""

    outcome = _outcome(
        helm_render_attempted=True,
        helm_available=True,
        helm_render_errors=[{"chart": "web", "error": "boom"}],
        helm_templates_skipped=["chart/templates/a.yaml"],
        parse_errors=[{"file": "b.yaml", "error": "bad"}],
    )

    _out, err = _emit(outcome, capsys)

    assert "failed to render" in err
    assert "skipped" in err
    assert "failed to parse" in err


def test_the_warnings_go_to_stderr_so_json_output_stays_parseable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`scan-k8s --format json > out.json` must not have warnings mixed into the file."""

    outcome = _outcome(parse_errors=[{"file": "b.yaml", "error": "bad"}])

    out, err = _emit(outcome, capsys)

    assert "failed to parse" in err
    assert "failed to parse" not in out
