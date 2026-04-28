"""CLI behaviour for bundled legacy profile ids."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
from tests.conftest import EXAMPLE_HARDENED, ROOT


def _run_module(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def test_evaluate_legacy_github_release_hardening_emits_stderr_warning() -> None:
    out_dir = ROOT / "out" / "pytest-legacy-alias-eval"
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-release-hardening",
            "--output-dir",
            str(out_dir),
            "--summary-only",
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    err = proc.stderr or ""
    assert "legacy" in err.lower()
    assert "github-release-hardening-1" in err


def test_profiles_json_lists_legacy_alias_with_flag() -> None:
    proc = _run_module(["profiles", "--format", "json"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    data = json.loads(proc.stdout)
    legacy = next(p for p in data["profiles"] if p["profile_id"] == "github-release-hardening")
    assert legacy["is_legacy_alias"] is True
    assert legacy["canonical_profile_id"] == "github-release-hardening-1"
    assert "assurance_mix" in legacy
    assert legacy["assurance_mix"]["det"] == 12


@pytest.mark.parametrize(
    "profile_id",
    [
        "github-level-3",
        "github-release-hardening-3",
        "aws-level-3",
        "aws-release-hardening-3",
        "azure-level-3",
        "azure-release-hardening-3",
    ],
)
def test_hardened_repo_extreme_profiles_have_zero_fail(profile_id: str) -> None:
    out_dir = ROOT / "out" / "pytest-extreme-profiles" / profile_id
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = _run_module(
        [
            "evaluate",
            "--target",
            str(EXAMPLE_HARDENED),
            "--profile",
            profile_id,
            "--output-dir",
            str(out_dir),
            "--summary-only",
        ]
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    report_path = out_dir / "evaluation-report.json"
    assert report_path.is_file(), "evaluate must write evaluation-report.json even with --summary-only"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary_by_status"].get("fail", 0) == 0
