"""Regression tests for scan-* operator messages that told the user something false.

Both cases are message-only defects with real cost: the first hands the operator a
command that cannot fix their problem, the second names a file they cannot find.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app
from oss_policy_kit.infrastructure.iac import scanner as iac_scanner
from oss_policy_kit.infrastructure.scanners.semgrep_adapter import SemgrepRunOutcome

runner = CliRunner()


def _flat(text: str) -> str:
    """Collapse Rich's terminal wrapping so assertions survive a narrow console."""

    return re.sub(r"\s+", " ", text)


@pytest.fixture
def hcl2_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the ``python-hcl2 is not installed`` branch regardless of the host env."""

    monkeypatch.setattr(iac_scanner, "hcl2_available", lambda: False)


def test_scan_iac_not_available_prints_the_command_that_installs_the_extra(tmp_path: Path, hcl2_absent: None) -> None:
    """An operator who copies the printed command must actually get the iac extra.

    Rich parsed ``[iac]`` as a markup tag and swallowed it, so the remediation read
    ``pip install 'oss-policy-kit'`` -- a no-op that reinstalls the same kit and
    leaves scan-iac permanently degraded to ``status: not_available``.
    """

    res = runner.invoke(app, ["scan-iac", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 0, res.output
    assert "oss-policy-kit[iac]" in _flat(res.output)


def test_scan_sast_failure_says_where_the_diagnostics_file_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A scan failure must locate its diagnostics file, without leaking the host path.

    The message named only ``sast-semgrep.json``; the file lives under a dot-directory
    the operator has no reason to know about, so the pointer was unusable.
    """

    def _err(*_a: object, **_k: object) -> SemgrepRunOutcome:
        return SemgrepRunOutcome(status="error", version="1.0", rulesets=["auto"], raw_stderr="boom")

    monkeypatch.setattr("oss_policy_kit.cli.scan_sast.run_semgrep", _err)
    res = runner.invoke(app, ["scan-sast", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 2
    flat = _flat(res.output)
    assert ".oss-policy-kit/evidence/sast-semgrep.json" in flat
    assert str(tmp_path) not in flat


def test_scan_iac_failure_says_where_the_diagnostics_file_is(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Same pointer defect on the sibling command, which shares the error branch."""

    def _err(*_a: object, **_k: object) -> iac_scanner.IacScanOutcome:
        return iac_scanner.IacScanOutcome(status="error", tool_version="1.0", diagnostics="boom")

    monkeypatch.setattr("oss_policy_kit.cli.scan_iac.run_scan", _err)
    res = runner.invoke(app, ["scan-iac", "--target", str(tmp_path), "--format", "human"])
    assert res.exit_code == 2
    flat = _flat(res.output)
    assert ".oss-policy-kit/evidence/iac-terraform.json" in flat
    assert str(tmp_path) not in flat
