"""Tests for ``scripts/v8-applicability-impact.py`` (ADR-028 control-impact analysis)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_impact_module():
    path = _REPO_ROOT / "scripts" / "v8-applicability-impact.py"
    spec = importlib.util.spec_from_file_location("v8_applicability_impact", path)
    assert spec and spec.loader, "could not locate scripts/v8-applicability-impact.py"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_profile_ids_lists_bundled_profiles() -> None:
    mod = _load_impact_module()
    ids = mod._profile_ids(mod.bundled_kit_root())
    assert "github-level-1" in ids
    assert len(ids) >= 50  # 56 bundled profiles at time of writing


def test_enable_attested_moves_prov_verify_to_attested_on_hardened() -> None:
    mod = _load_impact_module()
    kit_root = mod.bundled_kit_root()
    catalog = mod.load_catalog(kit_root / "controls" / "catalog.yaml")
    deltas = mod._diff_profile(EXAMPLE_HARDENED, "slsa-build-l2-1", kit_root, catalog)
    assert ("PROV-VERIFY-061", "pass", "attested") in deltas


def test_no_drift_on_empty_repo(tmp_path: Path) -> None:
    mod = _load_impact_module()
    kit_root = mod.bundled_kit_root()
    catalog = mod.load_catalog(kit_root / "controls" / "catalog.yaml")
    # An empty repo has no Dockerfile and no verified provenance evidence, so neither
    # opt-in moves any control.
    deltas = mod._diff_profile(tmp_path, "github-level-1", kit_root, catalog)
    assert deltas == []
