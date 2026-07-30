"""Shared pytest fixtures."""

import os
import shutil
from collections.abc import Iterator
from pathlib import Path

# Freeze the evaluation clock for the whole suite (incl. subprocess CLI tests, which
# inherit the environment). The kit honours SOURCE_DATE_EPOCH (reproducible-builds
# convention; see domain.models.utc_now) for every outcome-affecting clock read —
# evidence freshness, waiver expiry, attestation windows, report generated_at. Pinning
# it here makes fixture dates in tests/ and examples/ immune to calendar rot (the
# GOV-EVIDFRESH-054 90-day window silently expired on 2026-07-01 and broke the suite).
# 1781524800 == 2026-06-15T12:00:00Z; every bundled fixture date is on or before it.
os.environ.setdefault("SOURCE_DATE_EPOCH", "1781524800")

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_VULNERABLE = ROOT / "examples" / "vulnerable-repo"
EXAMPLE_HARDENED = ROOT / "examples" / "hardened-repo"
TEST_FIXTURES = ROOT / "tests" / "fixtures"
REPOSITORY_FIXTURES = TEST_FIXTURES / "repositories"
INVALID_WORKFLOW_FIXTURE = REPOSITORY_FIXTURES / "invalid-workflow-target"
REPO_WITH_SPACES_FIXTURE = REPOSITORY_FIXTURES / "repo with spaces"
AZURE_MINIMAL_FIXTURE = REPOSITORY_FIXTURES / "azure-minimal-target"
AZURE_HARDENED_FIXTURE = REPOSITORY_FIXTURES / "azure-hardened-target"
AWS_MINIMAL_FIXTURE = REPOSITORY_FIXTURES / "aws-minimal-target"
AWS_HARDENED_FIXTURE = REPOSITORY_FIXTURES / "aws-hardened-target"


@pytest.fixture
def semgrep_absent(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force the "semgrep is not on PATH" branch, independently of the host.

    The `scan-sast` not-available tests used to rely on the host simply not having Semgrep
    ("Semgrep is not installed in CI"). That passed in CI and failed on any contributor machine
    that does have it — and failed differently again when the installed Semgrep is broken, which
    surfaces as `error`/exit 2 rather than `not_available`. Pinning the condition here lets the
    real `run_semgrep` code path execute and reach the branch under test.

    Only the `semgrep` lookup is hidden; every other PATH resolution still goes to the real
    `shutil.which`, so nothing else the CLI does is disturbed.
    """

    real_which = shutil.which

    def _which(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        if Path(str(cmd)).stem.lower() == "semgrep":
            return None
        return real_which(cmd, *args, **kwargs)

    monkeypatch.setattr(shutil, "which", _which)
    yield


@pytest.fixture
def repo_root_vulnerable() -> Path:
    return EXAMPLE_VULNERABLE


@pytest.fixture
def repo_root_hardened() -> Path:
    return EXAMPLE_HARDENED
