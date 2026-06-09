"""Tests for the OSPS Baseline v2026.02.19 coverage map + generator.

These pin three things that matter for honesty:

1. **Data integrity** — every mapping references a real catalog control that is
   actually a member of the ``osps-baseline-2026-1`` profile, and a real OSPS
   criterion; the snapshot has exactly the 41 upstream criteria.
2. **Docs sync** — ``docs/osps-baseline-2026-coverage.md`` is the committed
   render of the generator (the ``--check`` gate, enforced in CI via the suite).
3. **No silent over/under-claim** — the per-level coverage counts are pinned, so
   adding a weak mapping (inflating coverage) or dropping one fails loudly, and
   the anti-overclaim wording contract is asserted on the generated doc.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOC_PATH = _REPO_ROOT / "docs" / "osps-baseline-2026-coverage.md"

# Upstream snapshot facts (transcribed from ossf/security-baseline tag v2026.02.19).
_TOTAL_CRITERIA = 41
_LEVEL_TOTALS = {1: 17, 2: 32, 3: 40}
# Honest coverage: criteria with >=1 clone-visible kit signal, per level.
# Pinned deliberately — a change here must be a conscious mapping decision.
_LEVEL_TOUCHED = {1: 11, 2: 17, 3: 21}
_DISTINCT_TOUCHED = 22


def _load_generator():
    path = _REPO_ROOT / "scripts" / "generate-osps-coverage.py"
    spec = importlib.util.spec_from_file_location("generate_osps_coverage", path)
    assert spec and spec.loader, "could not locate scripts/generate-osps-coverage.py"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen():
    return _load_generator()


@pytest.fixture(scope="module")
def data(gen):
    return gen._load_map(bundled_kit_root())


def test_snapshot_has_all_41_criteria(data) -> None:
    assert len(data["criteria"]) == _TOTAL_CRITERIA
    ids = [c["id"] for c in data["criteria"]]
    assert len(set(ids)) == _TOTAL_CRITERIA, "duplicate OSPS criterion id"
    families = {c["family"] for c in data["criteria"]}
    assert families == {"AC", "BR", "DO", "GV", "LE", "QA", "SA", "VM"}


def test_criteria_levels_match_upstream(data) -> None:
    by_id = {c["id"]: c for c in data["criteria"]}
    # Spot-check the non-obvious applicability sets (guards accidental edits).
    assert by_id["OSPS-AC-04"]["levels"] == [2, 3]
    assert by_id["OSPS-BR-07"]["levels"] == [1, 3]
    assert by_id["OSPS-VM-02"]["levels"] == [1]
    assert by_id["OSPS-QA-07"]["levels"] == [3]
    assert by_id["OSPS-DO-03"]["levels"] == [3]


def test_level_totals_match(data) -> None:
    for level, expected in _LEVEL_TOTALS.items():
        got = sum(1 for c in data["criteria"] if level in c["levels"])
        assert got == expected, f"L{level} total {got} != {expected}"


def test_mappings_reference_real_controls_in_profile(data) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    profile = load_profile_by_id(root, data["profile"])
    profile_ids = set(profile.control_ids)
    criteria_ids = {c["id"] for c in data["criteria"]}

    seen: set[str] = set()
    for entry in data["mappings"]:
        control = entry["control"]
        assert control not in seen, f"duplicate mapping for {control}"
        seen.add(control)
        assert control in catalog, f"{control} not in catalog"
        assert control in profile_ids, f"{control} not in {data['profile']} profile"
        assert entry["criteria"], f"{control} maps to no criteria"
        for crit in entry["criteria"]:
            assert crit in criteria_ids, f"{control} -> unknown criterion {crit}"

    for entry in data.get("aggregate_controls", []):
        assert entry["control"] in catalog


def test_coverage_counts_are_honest(gen, data) -> None:
    crit_controls = gen._criteria_to_controls(data)
    touched = {cid for cid, controls in crit_controls.items() if controls}
    assert len(touched) == _DISTINCT_TOUCHED

    by_id = {c["id"]: c for c in data["criteria"]}
    for level, expected in _LEVEL_TOUCHED.items():
        got = sum(1 for cid in touched if level in by_id[cid]["levels"])
        assert got == expected, f"L{level} touched {got} != {expected} (coverage drift?)"


def test_generated_doc_is_in_sync(gen) -> None:
    assert _DOC_PATH.is_file(), "run scripts/generate-osps-coverage.py"
    expected = gen._build().strip()
    actual = _DOC_PATH.read_text(encoding="utf-8").strip()
    assert actual == expected, (
        "docs/osps-baseline-2026-coverage.md is out of date; run `python scripts/generate-osps-coverage.py`"
    )


def test_doc_keeps_anti_overclaim_contract(gen) -> None:
    doc = gen._build()
    low = doc.lower()
    # Required honest framing.
    assert "advisory" in low
    assert "not a certification" in low or "not a conformance certification" in low
    assert "gaps are real" in low
    # Forbidden over-claims (must never appear).
    for banned in (
        "guarantees osps",
        "certifies osps",
        "osps certified",
        "fully compliant",
        "conformance certification of",
    ):
        assert banned not in low, f"over-claim phrase present: {banned!r}"


def test_check_mode_passes_when_in_sync(gen) -> None:
    assert gen.main(["--check"]) == 0
