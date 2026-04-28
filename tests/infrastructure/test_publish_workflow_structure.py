"""Structural regression tests for .github/workflows/publish-pypi.yml.

Guards against SBOM artefacts contaminating dist/ (which causes twine check failures).
"""

from __future__ import annotations

from pathlib import Path

import yaml

_WORKFLOW_PATH = Path(__file__).parents[2] / ".github" / "workflows" / "publish-pypi.yml"


def _load_workflow() -> dict:
    return yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))


def _build_steps(workflow: dict) -> list[dict]:
    return workflow["jobs"]["build"]["steps"]


def test_sbom_output_path_is_not_inside_dist() -> None:
    """SBOM must not be written to dist/ to avoid polluting wheel/sdist artifacts."""
    steps = _build_steps(_load_workflow())
    sbom_steps = [s for s in steps if "cyclonedx" in s.get("run", "").lower()]
    assert sbom_steps, "Expected at least one SBOM generation step"
    for step in sbom_steps:
        run_text: str = step["run"]
        assert "dist/sbom" not in run_text, "SBOM must not be written to dist/ — use artifacts/ or a separate path"
        assert "-o dist/" not in run_text, "SBOM output flag must not target dist/"


def test_dist_upload_artifact_does_not_include_sbom_path() -> None:
    """The 'dist' upload-artifact step must only cover the dist/ folder (no SBOM mixed in)."""
    steps = _build_steps(_load_workflow())
    upload_steps = [s for s in steps if isinstance(s.get("uses"), str) and "upload-artifact" in s["uses"]]
    dist_uploads = [s for s in upload_steps if s.get("with", {}).get("name") == "dist"]
    assert dist_uploads, "Expected an upload-artifact step named 'dist'"
    for step in dist_uploads:
        path_value: str = step["with"].get("path", "")
        assert "sbom" not in path_value.lower(), (
            "The dist artifact must not include SBOM files — keep them in a separate artifact"
        )


def test_sbom_has_dedicated_upload_artifact_step() -> None:
    """SBOM must be uploaded as its own artifact, separate from dist."""
    steps = _build_steps(_load_workflow())
    upload_steps = [s for s in steps if isinstance(s.get("uses"), str) and "upload-artifact" in s["uses"]]
    sbom_uploads = [s for s in upload_steps if s.get("with", {}).get("name") == "sbom"]
    assert sbom_uploads, "Expected a dedicated upload-artifact step named 'sbom' for the SBOM file"


def test_twine_check_step_precedes_sbom_generation() -> None:
    """twine check must run before SBOM generation so dist/ is clean when verified."""
    steps = _build_steps(_load_workflow())
    names_and_runs = [(i, s) for i, s in enumerate(steps)]

    def _is_twine_verify_step(step: dict) -> bool:
        run = str(step.get("run", ""))
        return "twine check" in run or "twine_check_dist" in run

    twine_idx = next((i for i, s in names_and_runs if _is_twine_verify_step(s)), None)
    sbom_idx = next(
        (i for i, s in names_and_runs if "cyclonedx" in s.get("run", "").lower()),
        None,
    )
    assert twine_idx is not None, "twine check step not found"
    assert sbom_idx is not None, "SBOM generation step not found"
    assert twine_idx < sbom_idx, f"twine check (step {twine_idx}) must come before SBOM generation (step {sbom_idx})"
