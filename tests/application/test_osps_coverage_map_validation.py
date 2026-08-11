"""Refusing an OSPS coverage map that would make the kit claim coverage it does not have.

The map says which OSPS Baseline criteria each control signals, and `osps-coverage` renders it
as a percentage. Every check here exists because the alternative is a number nobody can trust:
a duplicate criterion id would let one control satisfy the same criterion twice and inflate the
denominator's counterpart, an aggregate control that is not in the catalog would credit a
criterion to something the kit does not evaluate, and a map with no profile has nothing to
scope its claim to.

The file is bundled data, so a broken one means a broken build or a hand-edited install rather
than user input -- but it still has to fail with the file named rather than a traceback, since
that is what tells whoever hit it which file to look at.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from oss_policy_kit.application.loader import bundled_kit_root
from oss_policy_kit.application.osps_coverage import _load_raw, load_osps_coverage
from oss_policy_kit.domain.errors import LoadError

_MAP_REL = Path("frameworks") / "osps-baseline-2026.yaml"


@pytest.fixture
def kit_root(tmp_path: Path) -> Path:
    """A writable copy of the bundled kit data, so the map can be corrupted in place."""

    root = tmp_path / "data"
    shutil.copytree(bundled_kit_root(), root)
    return root


def _rewrite_map(root: Path, mutate: Any) -> None:
    path = root / _MAP_REL
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutate(raw)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Reading the file at all
# --------------------------------------------------------------------------- #


def test_a_map_that_is_not_valid_yaml_names_the_file(tmp_path: Path) -> None:
    path = tmp_path / "osps.yaml"
    path.write_text("profile: [unclosed\n", encoding="utf-8")
    with pytest.raises(LoadError, match="not valid YAML"):
        _load_raw(path)


@pytest.mark.parametrize("body", ["- one\n- two\n", "just a string\n", "42\n"])
def test_a_map_that_is_not_a_mapping_is_refused(body: str, tmp_path: Path) -> None:
    """Valid YAML, wrong shape: reading a list as a map would fail much later and less clearly."""

    path = tmp_path / "osps.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(LoadError, match="must be a YAML mapping"):
        _load_raw(path)


def test_the_bundled_map_loads(kit_root: Path) -> None:
    """The counterpart: every refusal below must be caused by the mutation, not the copy."""

    coverage = load_osps_coverage(kit_root)
    assert coverage.criteria
    assert coverage.profile


# --------------------------------------------------------------------------- #
# Refusals that protect the percentage
# --------------------------------------------------------------------------- #


def test_a_map_without_a_profile_has_nothing_to_scope_its_claim_to(kit_root: Path) -> None:
    _rewrite_map(kit_root, lambda raw: raw.__setitem__("profile", ""))
    with pytest.raises(LoadError, match="missing a 'profile'"):
        load_osps_coverage(kit_root)


def test_a_duplicate_criterion_id_is_refused(kit_root: Path) -> None:
    """Two entries for one criterion would be counted twice and the coverage overstated."""

    def _duplicate(raw: dict[str, Any]) -> None:
        raw["criteria"].append(dict(raw["criteria"][0]))

    _rewrite_map(kit_root, _duplicate)
    with pytest.raises(LoadError, match="duplicate criterion ids"):
        load_osps_coverage(kit_root)


def test_an_aggregate_control_outside_the_catalog_is_refused(kit_root: Path) -> None:
    """Crediting a criterion to a control the kit does not evaluate is a fabricated claim."""

    def _ghost(raw: dict[str, Any]) -> None:
        raw.setdefault("aggregate_controls", []).append({"control": "GOV-GHOST-999", "note": "n"})

    _rewrite_map(kit_root, _ghost)
    with pytest.raises(LoadError, match="GOV-GHOST-999"):
        load_osps_coverage(kit_root)
