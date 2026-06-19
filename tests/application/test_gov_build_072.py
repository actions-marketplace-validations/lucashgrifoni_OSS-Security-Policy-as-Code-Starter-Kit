"""GOV-BUILD-072 — source-code build instructions signal (OSPS-DO-07).

Covers the helper heuristic, the evaluator status mapping, and the wiring
(catalog + registry + osps-baseline-2026-1 profile + framework map).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.evaluators._shared import _has_build_instructions

REPO = Path(__file__).parents[2]
_DATA = REPO / "src" / "oss_policy_kit" / "data"


# --- helper heuristic --------------------------------------------------------


def test_helper_detects_makefile(tmp_path: Path) -> None:
    (tmp_path / "Makefile").write_text("build:\n\tpython -m build\n", encoding="utf-8")
    assert _has_build_instructions(tmp_path)


def test_helper_detects_readme_build_section(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Project\n\n## Building from source\n\nRun make.\n", encoding="utf-8")
    assert _has_build_instructions(tmp_path)


def test_helper_detects_tox_and_install_file(tmp_path: Path) -> None:
    (tmp_path / "tox.ini").write_text("[tox]\n", encoding="utf-8")
    assert _has_build_instructions(tmp_path)


def test_helper_absent_when_no_build_docs(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Project\n\nA short description with no build guidance.\n", encoding="utf-8")
    assert not _has_build_instructions(tmp_path)


# --- wiring ------------------------------------------------------------------


def test_control_is_registered() -> None:
    assert "GOV-BUILD-072" in EVALUATOR_REGISTRY


def test_control_in_catalog_as_governance_signal() -> None:
    catalog = yaml.safe_load((_DATA / "controls" / "catalog.yaml").read_text(encoding="utf-8"))
    ctrl = next((c for c in catalog["controls"] if c["id"] == "GOV-BUILD-072"), None)
    assert ctrl is not None
    assert ctrl["category"] == "governance"
    assert ctrl["assurance"] == "signal"


def test_control_in_osps_profile_and_framework_map() -> None:
    profile = yaml.safe_load((_DATA / "profiles" / "osps-baseline-2026-1" / "profile.yaml").read_text(encoding="utf-8"))
    assert "GOV-BUILD-072" in profile["controls"]
    fw = yaml.safe_load((_DATA / "frameworks" / "osps-baseline-2026.yaml").read_text(encoding="utf-8"))
    mapping = next((m for m in fw["mappings"] if m["control"] == "GOV-BUILD-072"), None)
    assert mapping is not None
    assert mapping["criteria"] == ["OSPS-DO-07"]


# --- end-to-end behavior (real subprocess) -----------------------------------


def _state(target: Path, out: Path) -> str | None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(target),
            "--profile",
            "osps-baseline-2026-1",
            "--output-dir",
            str(out),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    report = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    return next((c.get("state") for c in report["controls"] if c.get("id") == "GOV-BUILD-072"), None)


def test_pass_on_hardened_fixture(tmp_path: Path) -> None:
    # hardened-repo ships a Makefile, so the build-instructions signal passes.
    assert _state(REPO / "examples" / "hardened-repo", tmp_path) == "PASS"


def test_manual_review_on_vulnerable_fixture(tmp_path: Path) -> None:
    # vulnerable-repo has no build docs -> MANUAL_REVIEW_REQUIRED, serialized as UNKNOWN in reports/2.0.
    assert _state(REPO / "examples" / "vulnerable-repo", tmp_path) == "UNKNOWN"
