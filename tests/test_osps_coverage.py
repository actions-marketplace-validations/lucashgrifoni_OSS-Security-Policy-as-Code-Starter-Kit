"""Tests for the OSPS Baseline v2026.02.19 coverage map, generator, and CLI (ADR-037).

Three honesty guarantees are pinned here:

1. **Data integrity** — every mapping references a real catalog control that is a
   member of the ``osps-baseline-2026-1`` profile, and a real OSPS criterion; the
   snapshot has exactly the 41 upstream criteria. A tampered map raises LoadError.
2. **Docs sync** — ``docs/osps-baseline-2026-coverage.md`` is the committed render
   of the generator.
3. **No silent over/under-claim** — the per-level coverage counts are pinned, so
   adding a weak mapping (inflating coverage) or dropping one fails loudly, and the
   anti-overclaim wording contract is asserted on the generated doc.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from oss_policy_kit.application.loader import bundled_kit_root
from oss_policy_kit.application.osps_coverage import load_osps_coverage
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import LoadError
from tests.conftest import ROOT

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOC_PATH = _REPO_ROOT / "docs" / "osps-baseline-2026-coverage.md"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Upstream snapshot facts (transcribed from ossf/security-baseline tag v2026.02.19).
_TOTAL_CRITERIA = 41
_LEVEL_TOTALS = {1: 17, 2: 32, 3: 40}
# Honest coverage: criteria with >=1 clone-visible kit signal, per level.
# Pinned deliberately — a change here must be a conscious mapping decision.
_LEVEL_COVERED = {1: 11, 2: 18, 3: 22}
_DISTINCT_TOUCHED = 23


# --------------------------------------------------------------------------- #
# Application module: load_osps_coverage (single source of truth)
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def cov():
    return load_osps_coverage()


def test_snapshot_has_all_41_criteria(cov) -> None:
    assert len(cov.criteria) == _TOTAL_CRITERIA
    ids = [c.id for c in cov.criteria]
    assert len(set(ids)) == _TOTAL_CRITERIA
    assert {c.family for c in cov.criteria} == {"AC", "BR", "DO", "GV", "LE", "QA", "SA", "VM"}


def test_criteria_levels_match_upstream(cov) -> None:
    by_id = {c.id: c for c in cov.criteria}
    assert by_id["OSPS-AC-04"].levels == (2, 3)
    assert by_id["OSPS-BR-07"].levels == (1, 3)
    assert by_id["OSPS-VM-02"].levels == (1,)
    assert by_id["OSPS-QA-07"].levels == (3,)
    assert by_id["OSPS-DO-03"].levels == (3,)


def test_level_totals_and_coverage_are_honest(cov) -> None:
    by_level = {lc.level: lc for lc in cov.levels}
    for level, total in _LEVEL_TOTALS.items():
        assert by_level[level].total == total, f"L{level} total drift"
    for level, covered in _LEVEL_COVERED.items():
        assert by_level[level].covered == covered, f"L{level} coverage drift"
        assert by_level[level].gaps == _LEVEL_TOTALS[level] - covered
    touched = [c for c in cov.criteria if c.covered]
    assert len(touched) == _DISTINCT_TOUCHED
    assert len(cov.gap_criteria) == _TOTAL_CRITERIA - _DISTINCT_TOUCHED


def test_signals_carry_catalog_assurance(cov) -> None:
    by_id = {c.id: c for c in cov.criteria}
    sig = {s.control_id: s.assurance for s in by_id["OSPS-AC-01"].signals}
    assert sig == {"ORG-MFA-001": "evidence-backed"}
    assert by_id["OSPS-DO-01"].signals == ()  # an honest gap


def test_to_dict_is_json_serializable_and_consistent(cov) -> None:
    payload = json.loads(json.dumps(cov.to_dict()))
    assert payload["version"] == "v2026.02.19"
    assert len(payload["criteria"]) == _TOTAL_CRITERIA
    assert len(payload["gaps"]) == _TOTAL_CRITERIA - _DISTINCT_TOUCHED
    assert {lvl["level"]: lvl["covered"] for lvl in payload["levels"]} == _LEVEL_COVERED
    assert payload["aggregate_controls"], "aggregate control should be present"


# --------------------------------------------------------------------------- #
# Data-integrity: a tampered map must fail loudly (LoadError)
# --------------------------------------------------------------------------- #


def _tmp_kit_root(tmp_path: Path) -> Path:
    """A minimal bundled-kit root: real catalog + profiles, a writable frameworks dir."""
    src = bundled_kit_root()
    root = tmp_path / "data"
    shutil.copytree(src / "controls", root / "controls")
    shutil.copytree(src / "profiles", root / "profiles")
    (root / "frameworks").mkdir(parents=True)
    return root


def _write_map(root: Path, *, mappings: list[dict]) -> None:
    src = bundled_kit_root() / "frameworks" / "osps-baseline-2026.yaml"
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    data["mappings"] = mappings
    (root / "frameworks" / "osps-baseline-2026.yaml").write_text(
        yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
    )


@pytest.mark.parametrize(
    "mappings",
    [
        [{"control": "NOPE-CONTROL-999", "criteria": ["OSPS-AC-01"]}],  # unknown control
        [{"control": "GOV-WAIV-014", "criteria": ["OSPS-AC-01"]}],  # real control, not in profile
        [{"control": "ORG-MFA-001", "criteria": ["OSPS-ZZ-99"]}],  # unknown criterion
        [
            {"control": "ORG-MFA-001", "criteria": ["OSPS-AC-01"]},
            {"control": "ORG-MFA-001", "criteria": ["OSPS-AC-02"]},
        ],  # duplicate mapping
    ],
)
def test_tampered_map_raises_loaderror(tmp_path: Path, mappings: list[dict]) -> None:
    root = _tmp_kit_root(tmp_path)
    _write_map(root, mappings=mappings)
    with pytest.raises(LoadError):
        load_osps_coverage(root)


# --------------------------------------------------------------------------- #
# Generator: docs in sync + anti-overclaim wording
# --------------------------------------------------------------------------- #


def _load_generator():
    path = _REPO_ROOT / "scripts" / "generate-osps-coverage.py"
    spec = importlib.util.spec_from_file_location("generate_osps_coverage", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_doc_is_in_sync() -> None:
    gen = _load_generator()
    assert _DOC_PATH.is_file()
    assert _DOC_PATH.read_text(encoding="utf-8").strip() == gen._build().strip(), (
        "docs/osps-baseline-2026-coverage.md is out of date; run scripts/generate-osps-coverage.py"
    )


def test_doc_keeps_anti_overclaim_contract() -> None:
    low = _load_generator()._build().lower()
    assert "advisory" in low
    assert "not a certification" in low or "not a conformance certification" in low
    assert "gaps are real" in low
    for banned in ("guarantees osps", "certifies osps", "osps certified", "fully compliant"):
        assert banned not in low, f"over-claim phrase present: {banned!r}"


# --------------------------------------------------------------------------- #
# CLI: osps-coverage (subprocess, deterministic terminal)
# --------------------------------------------------------------------------- #


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "200"
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )


def test_cli_help_lists_osps_coverage() -> None:
    proc = _run(["--help"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "osps-coverage" in "".join(_ANSI_RE.sub("", proc.stdout + proc.stderr).split())


def test_cli_human_output_is_honest() -> None:
    proc = _run(["osps-coverage"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    out = proc.stdout
    assert "v2026.02.19" in out
    assert "11 / 17" in out and "18 / 32" in out and "22 / 40" in out
    assert "NOT a conformance certification" in out
    assert "OSPS-DO-01" in out  # a real gap is shown


def test_cli_json_output_shape() -> None:
    proc = _run(["osps-coverage", "--format", "json"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["version"] == "v2026.02.19"
    assert {lvl["level"]: lvl["covered"] for lvl in payload["levels"]} == _LEVEL_COVERED
    assert len(payload["criteria"]) == _TOTAL_CRITERIA


def test_cli_bad_format_exits_2() -> None:
    proc = _run(["osps-coverage", "--format", "xml"])
    assert proc.returncode == 2, proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# CLI in-process (CliRunner) — drives the render branches for coverage.
# --------------------------------------------------------------------------- #

_runner = CliRunner()


def test_cli_inprocess_human() -> None:
    res = _runner.invoke(app, ["osps-coverage"])
    assert res.exit_code == 0, res.output
    assert "11 / 17" in res.output
    assert "OSPS-DO-01" in res.output  # gap rendering branch
    assert "NOT a conformance certification" in res.output


def test_cli_inprocess_json() -> None:
    res = _runner.invoke(app, ["osps-coverage", "--format", "JSON"])  # case-insensitive
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert len(payload["criteria"]) == _TOTAL_CRITERIA


def test_cli_inprocess_bad_format_exit_2() -> None:
    res = _runner.invoke(app, ["osps-coverage", "--format", "xml"])
    assert res.exit_code == 2
