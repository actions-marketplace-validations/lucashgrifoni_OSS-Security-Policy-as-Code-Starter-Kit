"""An empty string passed to an enum flag must fail closed, never disable the feature.

Found by end-user validation on 2026-08-05. Two flags used the idiom::

    value = raw.strip().lower() if raw else None

An empty string is falsy, so ``--fail-on-severity ""`` skipped validation entirely and
``sev`` became ``None`` — indistinguishable from "flag not supplied". The CI gate then
silently did nothing and exited 0. Whitespace (``"  "``) is truthy, so it strips to ``""``,
fails validation and exits 2 — the same user intent, the opposite outcome.

The asymmetry is what makes this dangerous: ``--fail-on-severity ""`` is what a shell
produces from ``--fail-on-severity "$SEVERITY"`` when ``SEVERITY`` is unset, which is
exactly the case where a pipeline most needs the gate to stay armed.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

runner = CliRunner()


def _target_with_a_finding(tmp_path: Path) -> Path:
    """A target carrying one CRITICAL SARIF finding, so any armed gate must trip.

    The location matters: SARIF sources are discovered at a fixed path per tool —
    ``.oss-policy-kit/evidence/sast/gitleaks.sarif.json`` — by exact name, not by
    ``tool.driver.name`` inside the document.
    """

    target = tmp_path / "repo"
    (target / ".oss-policy-kit" / "evidence" / "sast").mkdir(parents=True)
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "gitleaks", "rules": [{"id": "R1"}]}},
                "results": [
                    {
                        "ruleId": "R1",
                        "level": "error",
                        "message": {"text": "hardcoded secret"},
                        "properties": {"security-severity": "9.8"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    (target / ".oss-policy-kit" / "evidence" / "sast" / "gitleaks.sarif.json").write_text(
        json.dumps(sarif), encoding="utf-8"
    )
    return target


def test_correlate_findings_empty_fail_on_severity_exits_2(tmp_path: Path) -> None:
    """``--fail-on-severity ""`` must be rejected, not treated as "no gate"."""

    target = _target_with_a_finding(tmp_path)
    res = runner.invoke(
        app,
        [
            "correlate-findings",
            "--target",
            str(target),
            "--output",
            str(tmp_path / "findings.json"),
            "--fail-on-severity",
            "",
        ],
    )
    assert res.exit_code == 2, f"empty value must fail closed, got {res.exit_code}: {res.output}"


def test_correlate_findings_whitespace_fail_on_severity_also_exits_2(tmp_path: Path) -> None:
    """Whitespace already failed correctly — pin it so the two stay symmetric."""

    target = _target_with_a_finding(tmp_path)
    res = runner.invoke(
        app,
        [
            "correlate-findings",
            "--target",
            str(target),
            "--output",
            str(tmp_path / "findings.json"),
            "--fail-on-severity",
            "   ",
        ],
    )
    assert res.exit_code == 2, res.output


def test_correlate_findings_valid_severity_still_arms_the_gate(tmp_path: Path) -> None:
    """The fix must not break the working path: a real value still trips on a finding.

    The fixture normalises to HIGH, so ``--fail-on-severity high`` is the threshold that
    must trip. Pinned at the level the finding actually reaches rather than at
    ``critical``, so this test fails if the gate stops firing — not if the severity
    mapping is retuned.
    """

    target = _target_with_a_finding(tmp_path)
    res = runner.invoke(
        app,
        [
            "correlate-findings",
            "--target",
            str(target),
            "--output",
            str(tmp_path / "findings.json"),
            "--fail-on-severity",
            "high",
        ],
    )
    assert res.exit_code == 1, f"a HIGH finding must trip --fail-on-severity high: {res.output}"


def test_correlate_findings_gate_below_threshold_does_not_trip(tmp_path: Path) -> None:
    """A HIGH finding must not trip a ``critical`` gate — the threshold is a threshold."""

    target = _target_with_a_finding(tmp_path)
    res = runner.invoke(
        app,
        [
            "correlate-findings",
            "--target",
            str(target),
            "--output",
            str(tmp_path / "findings.json"),
            "--fail-on-severity",
            "critical",
        ],
    )
    assert res.exit_code == 0, res.output


def test_correlate_findings_without_the_flag_does_not_gate(tmp_path: Path) -> None:
    """Omitting the flag is the one case that legitimately means "no gate"."""

    target = _target_with_a_finding(tmp_path)
    res = runner.invoke(
        app,
        ["correlate-findings", "--target", str(target), "--output", str(tmp_path / "findings.json")],
    )
    assert res.exit_code == 0, res.output


def test_profiles_empty_family_exits_2() -> None:
    """``profiles --family ""`` silently listed all 56 profiles; a typo exited 2."""

    res = runner.invoke(app, ["profiles", "--family", ""])
    assert res.exit_code == 2, f"empty --family must fail closed, got {res.exit_code}: {res.output}"


def test_profiles_whitespace_family_exits_2() -> None:
    res = runner.invoke(app, ["profiles", "--family", "  "])
    assert res.exit_code == 2, res.output


def test_profiles_valid_family_still_filters() -> None:
    res = runner.invoke(app, ["profiles", "--family", "github", "--format", "json"])
    assert res.exit_code == 0, res.output


def test_profiles_without_family_lists_everything() -> None:
    res = runner.invoke(app, ["profiles", "--format", "json"])
    assert res.exit_code == 0, res.output
