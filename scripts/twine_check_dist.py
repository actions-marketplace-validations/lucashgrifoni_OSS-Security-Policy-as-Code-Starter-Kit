#!/usr/bin/env python3
"""Run ``twine check`` on built artifacts using explicit paths.

Windows PowerShell does not expand ``dist/*`` the same way as POSIX shells, so
``python -m twine check dist/*`` can silently check nothing or fail oddly.
This helper resolves the sdist and wheel that match the current
``pyproject.toml`` version and invokes twine with concrete paths.

Usage (from repository root, after ``python -m build``)::

    python scripts/twine_check_dist.py
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectDist:
    """Project metadata needed to resolve built artifacts."""

    dist_stem: str
    version: str


def _load_project_dist(repo_root: Path) -> ProjectDist:
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.is_file():
        raise SystemExit(f"Missing {pyproject}.")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project")
    if not isinstance(project, dict):
        raise SystemExit(f"Missing [project] table in {pyproject}.")
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        raise SystemExit(f"Missing project.name/project.version in {pyproject}.")
    return ProjectDist(dist_stem=name.replace("-", "_"), version=version)


def resolve_dist_artifacts(repo_root: Path) -> list[Path]:
    dist = repo_root / "dist"
    if not dist.is_dir():
        raise SystemExit("dist/ is missing; run `python -m build` first.")

    project = _load_project_dist(repo_root)
    sdist = dist / f"{project.dist_stem}-{project.version}.tar.gz"
    if not sdist.is_file():
        raise SystemExit(f"No sdist matching {sdist.relative_to(repo_root)}")

    wheels = sorted(dist.glob(f"{project.dist_stem}-{project.version}-*.whl"))
    if not wheels:
        raise SystemExit(f"No wheel matching dist/{project.dist_stem}-{project.version}-*.whl")
    if len(wheels) > 1:
        joined = ", ".join(str(path.name) for path in wheels)
        raise SystemExit(f"Expected exactly one wheel for {project.version}, found {len(wheels)}: {joined}")
    return [sdist, wheels[0]]


def main() -> int:
    repo_root = Path.cwd()
    try:
        paths = [str(path) for path in resolve_dist_artifacts(repo_root)]
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 1
    cmd = [sys.executable, "-m", "twine", "check", *paths]
    return int(subprocess.call(cmd))


if __name__ == "__main__":
    raise SystemExit(main())
