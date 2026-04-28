"""Guardrails for public-release readiness assets and references."""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

_REQUIRED_ARTIFACTS: tuple[Path, ...] = (
    _REPO_ROOT / "ROADMAP.md",
    _REPO_ROOT / "docs" / "public-release-readiness.md",
    _REPO_ROOT / "docs" / "publication-traceability-matrix.md",
    _REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "false_positive.yml",
)

_PUBLIC_DOCS: tuple[Path, ...] = (
    _REPO_ROOT / "README.md",
    _REPO_ROOT / "CONTRIBUTING.md",
    _REPO_ROOT / "SECURITY.md",
    _REPO_ROOT / "ROADMAP.md",
    _REPO_ROOT / "docs" / "README.md",
    _REPO_ROOT / "docs" / "release-readiness.md",
    _REPO_ROOT / "docs" / "public-release-readiness.md",
    _REPO_ROOT / "docs" / "publication-traceability-matrix.md",
)


def test_publication_readiness_artifacts_exist() -> None:
    for path in _REQUIRED_ARTIFACTS:
        assert path.is_file(), f"missing required publication artifact: {path.relative_to(_REPO_ROOT)}"


def test_public_docs_reference_publication_artifacts() -> None:
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    docs_index = (_REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    contributing = (_REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

    assert "docs/public-release-readiness.md" in readme
    assert "docs/publication-traceability-matrix.md" in readme
    assert "ROADMAP.md" in readme
    assert "rather than a separate roadmap file" not in readme
    assert "public-release-readiness.md" in docs_index
    assert "publication-traceability-matrix.md" in docs_index
    assert "ROADMAP.md" in docs_index
    assert "False positives" in contributing


def test_false_positive_template_mentions_reproducibility() -> None:
    template = (_REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "false_positive.yml").read_text(encoding="utf-8")
    assert "false-positive" in template
    assert "Steps to reproduce" in template
    assert "smallest reliable reproduction" in template


def test_public_docs_do_not_expose_maintainer_local_paths() -> None:
    for path in _PUBLIC_DOCS:
        text = path.read_text(encoding="utf-8")
        assert "C:\\Users\\" not in text, f"{path.relative_to(_REPO_ROOT)} must not expose Windows user paths"
