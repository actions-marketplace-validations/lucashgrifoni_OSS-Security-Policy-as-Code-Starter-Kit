"""Minimal guardrails against factual drift in public docs (baseline counts, retired wording)."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.loader import bundled_kit_root, load_profile_by_id

_REPO_ROOT = Path(__file__).resolve().parents[2]

_PRIORITY_DOCS: tuple[Path, ...] = (
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "docs" / "adoption-guide.md",
    _REPO_ROOT / "docs" / "evidence-pack.md",
    _REPO_ROOT / "docs" / "policy-data-lifecycle.md",
    _REPO_ROOT / "docs" / "recommended-adoption-playbook.md",
)

_RETIRED_PHRASES: tuple[str, ...] = (
    "pass: 16",
    "63 passed",
    "all 62 bundled controls",
)


def test_github_level_1_bundle_size_is_fourteen() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "github-level-1")
    assert len(spec.control_ids) == 14


def test_priority_docs_avoid_retired_numeric_claims() -> None:
    for path in _PRIORITY_DOCS:
        text = path.read_text(encoding="utf-8")
        for phrase in _RETIRED_PHRASES:
            assert phrase not in text, f"{path.relative_to(_REPO_ROOT)} must not contain {phrase!r}"


def test_adoption_guide_does_not_feature_deprecated_audit_sbom_controls() -> None:
    adoption = (_REPO_ROOT / "docs" / "adoption-guide.md").read_text(encoding="utf-8")
    assert "SEC-AUDIT-016" not in adoption
    assert "CI-SBOM-017" not in adoption
