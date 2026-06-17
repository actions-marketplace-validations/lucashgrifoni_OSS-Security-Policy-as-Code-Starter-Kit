"""v8.0.0 (ADR-041): the applicability engine and ATTESTED resolution are ON by default.

These lock in the breaking default flip at the CLI surface and verify the opt-out flags
(`--no-applicability-engine` / `--no-enable-attested`) restore pre-v8.0.0 behavior. Run via a
real subprocess so the typer defaults are exercised exactly as an end user gets them.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).parents[2]
VULN = REPO / "examples" / "vulnerable-repo"
HARDENED = REPO / "examples" / "hardened-repo"


def _evaluate(target: Path, profile: str, out: Path, *flags: str) -> dict:
    cmd = [
        sys.executable,
        "-m",
        "oss_policy_kit",
        "evaluate",
        "--target",
        str(target),
        "--profile",
        profile,
        "--output-dir",
        str(out),
        *flags,
    ]
    subprocess.run(
        cmd,
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    return json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))


def _state(report: dict, cid: str) -> str | None:
    for c in report["controls"]:
        if c.get("id") == cid:
            return c.get("state")
    return None


def test_applicability_engine_on_by_default(tmp_path: Path) -> None:
    # vulnerable-repo has no Terraform; under the v8.0.0 default the control is NOT_APPLICABLE,
    # not the pre-v8.0.0 UNKNOWN/MANUAL_REVIEW_REQUIRED.
    rep = _evaluate(VULN, "iac-terraform-baseline-1", tmp_path / "default")
    assert _state(rep, "IAC-TF-001") == "NOT_APPLICABLE"


def test_applicability_engine_opt_out_restores_pre_v8(tmp_path: Path) -> None:
    rep = _evaluate(VULN, "iac-terraform-baseline-1", tmp_path / "optout", "--no-applicability-engine")
    assert _state(rep, "IAC-TF-001") != "NOT_APPLICABLE"


def test_attested_on_by_default(tmp_path: Path) -> None:
    # hardened-repo carries verified provenance evidence; PROV-VERIFY-061 resolves to ATTESTED.
    rep = _evaluate(HARDENED, "github-level-3", tmp_path / "attested")
    assert _state(rep, "PROV-VERIFY-061") == "ATTESTED"


def test_attested_opt_out_restores_pass(tmp_path: Path) -> None:
    rep = _evaluate(HARDENED, "github-level-3", tmp_path / "noattest", "--no-enable-attested")
    assert _state(rep, "PROV-VERIFY-061") == "PASS"
