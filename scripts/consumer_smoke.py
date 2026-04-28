#!/usr/bin/env python3
"""Official consumer smoke test: isolated venv, wheel install, CLI exercises.

Run from the repository root after ``python -m build``. See docs/packaging-and-release.md.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class SmokeStep:
    """One CLI invocation result."""

    name: str
    argv: list[str]
    exit_code: int
    expected_exit_code: int | None


@dataclass(frozen=True)
class ProjectDist:
    """Project metadata needed to resolve built artifacts."""

    dist_stem: str
    version: str


_CAPTURE_TEXT_KWARGS = {
    "capture_output": True,
    "text": True,
    "encoding": "utf-8",
    "errors": "replace",
}


def _py_exe(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


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


def resolve_wheel(repo_root: Path, wheel_glob: str | None = None) -> Path:
    project = _load_project_dist(repo_root)
    pattern = wheel_glob or f"dist/{project.dist_stem}-{project.version}-*.whl"
    matches = sorted(repo_root.glob(pattern))
    if not matches:
        msg = f"No wheel found under {repo_root} matching {pattern}. Run python -m build first."
        raise SystemExit(msg)
    if len(matches) > 1:
        joined = ", ".join(str(path.name) for path in matches)
        msg = f"Expected exactly one wheel for pattern {pattern}, found {len(matches)}: {joined}"
        raise SystemExit(msg)
    return matches[0]


def _run(py: Path, argv: list[str], *, cwd: Path) -> int:
    proc = subprocess.run([str(py), *argv], cwd=cwd, **_CAPTURE_TEXT_KWARGS)
    return int(proc.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: current directory).",
    )
    parser.add_argument(
        "--wheel-glob",
        default=None,
        help=(
            "Glob relative to repo root for the wheel. "
            "Default: the wheel matching the current project version in pyproject.toml."
        ),
    )
    parser.add_argument(
        "--venv-dir",
        type=Path,
        default=None,
        help="Virtualenv directory (default: <repo-root>/.consumer-smoke-venv).",
    )
    parser.add_argument(
        "--output-summary",
        type=Path,
        default=None,
        help="Write JSON summary here (default: <repo-root>/out/consumer-smoke-summary.json).",
    )
    parser.add_argument(
        "--keep-venv",
        action="store_true",
        help="Do not delete the venv after the run.",
    )
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    venv_dir = (args.venv_dir or (repo_root / ".consumer-smoke-venv")).resolve()
    out_summary = args.output_summary or (repo_root / "out" / "consumer-smoke-summary.json")
    wheel = resolve_wheel(repo_root, args.wheel_glob)

    if venv_dir.is_dir():
        shutil.rmtree(venv_dir)

    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        cwd=repo_root,
        check=True,
    )
    py = _py_exe(venv_dir)

    subprocess.run(
        [str(py), "-m", "pip", "install", "--upgrade", "pip", str(wheel)],
        cwd=repo_root,
        check=True,
    )

    proc_kit = subprocess.run(
        [str(py), "-c", "from oss_policy_kit.application.loader import bundled_kit_root; print(bundled_kit_root())"],
        cwd=repo_root,
        **_CAPTURE_TEXT_KWARGS,
        check=True,
    )
    kit_root = proc_kit.stdout.strip()
    examples_hardened = repo_root / "examples" / "hardened-repo"
    examples_vuln = repo_root / "examples" / "vulnerable-repo"
    invalid_wf = repo_root / "tests" / "fixtures" / "repositories" / "invalid-workflow-target"
    waivers = examples_hardened / "waivers" / "waivers.yaml"

    steps: list[SmokeStep] = []

    def add(name: str, argv: list[str], expect: int | None = 0) -> None:
        code = _run(py, argv, cwd=repo_root)
        steps.append(SmokeStep(name=name, argv=argv, exit_code=code, expected_exit_code=expect))

    add("version", ["-m", "oss_policy_kit", "--version"], 0)
    add("help_root", ["-m", "oss_policy_kit", "--help"], 0)
    add("evaluate_help", ["-m", "oss_policy_kit", "evaluate", "--help"], 0)
    add(
        "selfcheck",
        [
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(repo_root),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(repo_root / "out" / "consumer-smoke-selfcheck"),
            "--format",
            "json",
        ],
        0,
    )
    add(
        "hardened",
        [
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(examples_hardened),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(repo_root / "out" / "consumer-smoke-hardened"),
        ],
        0,
    )
    add(
        "vulnerable",
        [
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(examples_vuln),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(repo_root / "out" / "consumer-smoke-vuln"),
        ],
        0,
    )
    add(
        "vulnerable_fail_on_fail",
        [
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(examples_vuln),
            "--profile",
            "github-level-1",
            "--output-dir",
            str(repo_root / "out" / "consumer-smoke-vuln-fail"),
            "--fail-on",
            "fail",
        ],
        1,
    )
    if invalid_wf.is_dir():
        add(
            "invalid_fail_on_degraded",
            [
                "-m",
                "oss_policy_kit",
                "evaluate",
                "--target",
                str(invalid_wf),
                "--profile",
                "github-level-1",
                "--output-dir",
                str(repo_root / "out" / "consumer-smoke-invalid-degraded"),
                "--fail-on",
                "degraded",
            ],
            1,
        )
    add(
        "waivers",
        [
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(examples_hardened),
            "--profile",
            "github-level-1",
            "--waivers",
            str(waivers),
            "--output-dir",
            str(repo_root / "out" / "consumer-smoke-waivers"),
        ],
        0,
    )
    add(
        "kit_root_override",
        [
            "-m",
            "oss_policy_kit",
            "evaluate",
            "--target",
            str(examples_hardened),
            "--profile",
            "github-level-1",
            "--kit-root",
            kit_root,
            "--output-dir",
            str(repo_root / "out" / "consumer-smoke-kit-root"),
        ],
        0,
    )

    mismatches = [
        step.name for step in steps if step.expected_exit_code is not None and step.exit_code != step.expected_exit_code
    ]
    payload = {
        "repo_root": str(repo_root),
        "wheel": str(wheel),
        "venv_dir": str(venv_dir),
        "kit_root_resolved": kit_root,
        "all_expected_matched": len(mismatches) == 0,
        "mismatched_steps": mismatches,
        "steps": [asdict(step) for step in steps],
    }

    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md_path = out_summary.with_suffix(".md")
    lines = [
        "# Consumer smoke summary",
        "",
        f"- Wheel: `{wheel}`",
        f"- All expectations matched: **{payload['all_expected_matched']}**",
        "",
        "| Step | Exit | Expected |",
        "| --- | ---: | ---: |",
    ]
    for step in steps:
        exp = "" if step.expected_exit_code is None else str(step.expected_exit_code)
        lines.append(f"| {step.name} | {step.exit_code} | {exp} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if not args.keep_venv:
        shutil.rmtree(venv_dir, ignore_errors=True)

    if mismatches:
        print(f"Smoke mismatches: {', '.join(mismatches)}", file=sys.stderr)
        return 1
    print(f"OK: wrote {out_summary} and {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
