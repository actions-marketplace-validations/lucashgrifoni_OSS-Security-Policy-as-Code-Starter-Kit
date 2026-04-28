"""v4.0.0: removed controls have no catalog entry and no evaluator implementation."""

from __future__ import annotations

from oss_policy_kit.application.evaluators import EVALUATOR_REGISTRY
from oss_policy_kit.application.loader import REMOVED_CONTROL_IDS, bundled_kit_root, load_catalog


def test_removed_controls_absent_from_catalog_and_registry() -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    for rid in REMOVED_CONTROL_IDS:
        assert rid not in catalog
        assert rid not in EVALUATOR_REGISTRY
