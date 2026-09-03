"""v10.0.7 regression tests for ``recommend-profile`` heuristics.

Two defects found by clean-room validation of the published v10.0.6 wheel:

1. ``recommend-profile`` told adopters that ``github-actions-policy.json`` and
   ``github-release-immutability.json`` -- both written by ``scaffold-evidence
   --platform github`` and both read back by ``evaluate`` -- "do not match any
   bundled schema and will be ignored", and offered to remove them. v10.0.6 had
   fixed the same class for one filename by appending a string; these tests pin
   the *invariant* instead (every filename the kit writes or reads is recognized).
2. A Python repository carrying a sidecar ``package.json`` was announced as a
   Node.js project, because ``init`` takes the first stack signal and the Node
   detector ran first regardless of evidence strength.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from tests.conftest import ROOT

from oss_policy_kit.application import profile_hints as ph
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.application.init_planner import build_init_plan
from oss_policy_kit.application.profile_hints import build_profile_recommendation

_UNRECOGNIZED_SIGNAL = "evidence_json_unrecognized_filenames"
_EVALUATOR_DIRS = (
    ROOT / "src" / "oss_policy_kit" / "application" / "evaluators",
    ROOT / "src" / "oss_policy_kit" / "application",
)
#: Matches ``ctx.repo_root / _KIT_DIR / "evidence" / "<name>.json"`` in evaluator source.
_EVIDENCE_READ_RE = re.compile(r'"evidence"\s*/\s*"([A-Za-z0-9._-]+\.json)"')


def _signal_ids(repo_root: Path) -> set[str]:
    return {s["id"] for s in build_profile_recommendation(repo_root).signals_detected}


def _signal_detail(repo_root: Path, signal_id: str) -> str:
    rec = build_profile_recommendation(repo_root)
    return next(s["detail"] for s in rec.signals_detected if s["id"] == signal_id)


def _primary_stack(repo_root: Path) -> str | None:
    plan = build_init_plan(
        target=repo_root,
        forced_profile=None,
        forced_platform=None,
        fail_on="fail",
        output_dir="reports",
        with_waivers=False,
        with_evidence=False,
        with_workflow=False,
        force=False,
        dry_run=True,
    )
    return plan.primary_stack


def _write_python_project(repo_root: Path) -> None:
    (repo_root / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8")
    src = repo_root / "src"
    src.mkdir(exist_ok=True)
    (src / "app.py").write_text("def main() -> None:\n    return None\n", encoding="utf-8")


def _write_sidecar_package_json(repo_root: Path) -> None:
    """A devDependency-only package.json: linting/docs tooling, not the project."""

    (repo_root / "package.json").write_text(
        json.dumps({"name": "docs-tooling", "private": True, "devDependencies": {"markdownlint-cli": "^0.41.0"}}),
        encoding="utf-8",
    )


# --- Defect 1: evidence the kit wrote must never be called unrecognized ------


@pytest.mark.parametrize("platform", ["github", "gitlab", "azure", "aws"])
def test_scaffolded_evidence_is_never_reported_as_unrecognized(tmp_path: Path, platform: str) -> None:
    """The invariant: every file ``scaffold-evidence`` writes is a recognized filename.

    Telling an adopter to rename or remove ``github-actions-policy.json`` /
    ``github-release-immutability.json`` destroys evidence that ``evaluate``
    genuinely reads (GH-ACTPOL / GH-IMMUTREL flip away from PASS).
    """

    scaffold_evidence_files(tmp_path, platform, force=True)
    written = sorted(p.name for p in (tmp_path / ".oss-policy-kit" / "evidence").glob("*.json"))
    assert written, "scaffold-evidence wrote no JSON; the fixture is not exercising anything"

    ids = _signal_ids(tmp_path)
    assert _UNRECOGNIZED_SIGNAL not in ids, (
        f"scaffold-evidence --platform {platform} wrote {written}, and recommend-profile "
        f"then advised removing some of them: {_signal_detail(tmp_path, _UNRECOGNIZED_SIGNAL)}"
    )


@pytest.mark.parametrize("platform", ["github", "gitlab", "azure", "aws"])
def test_scaffolded_evidence_does_not_trigger_the_non_bundled_note(tmp_path: Path, platform: str) -> None:
    """The companion note must not fire for filenames the kit itself produces."""

    scaffold_evidence_files(tmp_path, platform, force=True)
    rec = build_profile_recommendation(tmp_path)
    assert not any("non-bundled filenames" in note for note in rec.notes)


def test_github_org_posture_evidence_counts_as_github_evidence(tmp_path: Path) -> None:
    """Both filenames are GitHub-shaped evidence, so they belong in the GitHub bucket."""

    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    for name in ("github-actions-policy.json", "github-release-immutability.json"):
        (ev / name).write_text(json.dumps({"schema_version": "x"}), encoding="utf-8")

    ids = _signal_ids(tmp_path)
    assert "github_evidence_json_files" in ids
    assert _UNRECOGNIZED_SIGNAL not in ids
    detail = _signal_detail(tmp_path, "github_evidence_json_files")
    assert "github-actions-policy.json" in detail
    assert "github-release-immutability.json" in detail


def test_recognized_filenames_are_derived_from_the_bundled_schema_directory() -> None:
    """The list must come from the source of truth, not from a hand-maintained string list.

    ``ai-system-technical-doc.json`` is schema-backed but deliberately absent from the
    static fallback floor, so it is only recognized when the derivation is live.
    """

    derived = ph.schema_backed_evidence_filenames()
    assert "ai-system-technical-doc.json" in derived
    assert "ai-system-technical-doc.json" not in ph._EVIDENCE_FILENAME_FLOOR
    assert "ai-system-technical-doc.json" in ph.recognized_evidence_filenames()
    for name in ("github-actions-policy.json", "github-release-immutability.json", "sast-semgrep.json"):
        assert name in derived, f"{name} lost its bundled schema; the derivation would silently shrink"


def test_static_fallback_floor_stays_redundant_with_the_derivation() -> None:
    """A stale floor entry means a schema was renamed and the buckets are drifting."""

    assert ph.schema_backed_evidence_filenames() >= ph._EVIDENCE_FILENAME_FLOOR


def test_every_evidence_filename_an_evaluator_reads_is_recognized() -> None:
    """Scan the evaluators for the evidence documents they read and demand recognition.

    This is the check that generalises the defect: a new evaluator reading a new
    ``.oss-policy-kit/evidence/<name>.json`` must not make ``recommend-profile``
    advise deleting it.
    """

    read_names: set[str] = set()
    for directory in _EVALUATOR_DIRS:
        for source in sorted(directory.glob("*.py")):
            read_names.update(_EVIDENCE_READ_RE.findall(source.read_text(encoding="utf-8")))
    assert len(read_names) > 15, f"source scan found only {sorted(read_names)}; the regex has drifted"

    recognized = ph.recognized_evidence_filenames()
    assert not (read_names - recognized), (
        f"evaluators read evidence that recommend-profile calls unrecognized: {sorted(read_names - recognized)}"
    )


def test_a_genuinely_unknown_filename_is_still_surfaced(tmp_path: Path) -> None:
    """Widening recognition must not silence the signal for stale or typo'd files."""

    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "branch-protecton.json").write_text(json.dumps({"schema_version": "x"}), encoding="utf-8")

    assert _UNRECOGNIZED_SIGNAL in _signal_ids(tmp_path)
    assert "branch-protecton.json" in _signal_detail(tmp_path, _UNRECOGNIZED_SIGNAL)


# --- Defect 2: rank stacks by evidence strength, not by detector order -------


def test_python_project_with_a_sidecar_package_json_is_not_announced_as_node(tmp_path: Path) -> None:
    """The reported case: pyproject.toml + src/app.py + a devDependency-only package.json."""

    _write_python_project(tmp_path)
    _write_sidecar_package_json(tmp_path)

    assert _primary_stack(tmp_path) == "Python"


def test_adding_a_package_lock_does_not_rebrand_a_python_project(tmp_path: Path) -> None:
    """Adding package-lock.json "changes nothing" was the reporter's follow-up probe."""

    _write_python_project(tmp_path)
    _write_sidecar_package_json(tmp_path)
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3}), encoding="utf-8")

    assert _primary_stack(tmp_path) == "Python"


def test_requirements_txt_plus_package_json_is_not_announced_as_node(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    _write_sidecar_package_json(tmp_path)

    assert _primary_stack(tmp_path) == "Python"


def test_the_strongest_stack_signal_is_emitted_first(tmp_path: Path) -> None:
    """``signals_detected`` is the ranking a single-value consumer reads."""

    _write_python_project(tmp_path)
    _write_sidecar_package_json(tmp_path)

    ids = [s["id"] for s in build_profile_recommendation(tmp_path).signals_detected]
    stack_ids = [sid for sid in ids if sid in ph._STACK_SIGNAL_LABELS]
    assert stack_ids[0] == "python_pyproject"
    assert "node_js" in stack_ids, "the weaker stack must still be reported, not dropped"


def test_a_real_node_project_is_still_ranked_as_node(tmp_path: Path) -> None:
    """Guard against overcorrecting into "always Python"."""

    (tmp_path / "package.json").write_text(json.dumps({"name": "app", "dependencies": {}}), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3}), encoding="utf-8")

    assert _primary_stack(tmp_path) == "Node.js"


def test_a_node_lockfile_outranks_a_bare_requirements_txt(tmp_path: Path) -> None:
    """Ranking is by evidence strength, not by a fixed language preference."""

    (tmp_path / "package.json").write_text(json.dumps({"name": "app"}), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3}), encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")

    assert _primary_stack(tmp_path) == "Node.js"


def test_a_polyglot_repository_reports_every_stack_it_found(tmp_path: Path) -> None:
    """One primary stack is a convenience, so say out loud that others were seen."""

    _write_python_project(tmp_path)
    _write_sidecar_package_json(tmp_path)

    rec = build_profile_recommendation(tmp_path)
    ranked_note = next((n for n in rec.notes if "Multiple language stacks detected" in n), None)
    assert ranked_note is not None
    assert ranked_note.index("Python") < ranked_note.index("Node.js")


def test_a_single_stack_repository_gets_no_multi_stack_note(tmp_path: Path) -> None:
    _write_python_project(tmp_path)

    rec = build_profile_recommendation(tmp_path)
    assert not any("Multiple language stacks detected" in n for n in rec.notes)


def test_stack_ranking_does_not_change_the_suggested_profile(tmp_path: Path) -> None:
    """The suggested PROFILE was already correct; fixing the label must not move it."""

    _write_python_project(tmp_path)
    _write_sidecar_package_json(tmp_path)

    rec = build_profile_recommendation(tmp_path)
    assert [s["profile_id"] for s in rec.suggestions] == ["github-level-1"]
    based_on = rec.suggestions[0]["based_on"]
    assert "python_pyproject" in based_on
    assert "node_js" in based_on


def test_a_containerised_python_repo_still_reports_the_container_stack(tmp_path: Path) -> None:
    """Container packaging keeps its historical lead position over the language label."""

    _write_python_project(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")

    assert _primary_stack(tmp_path) == "Container (Docker)"


def test_no_stack_marker_at_all_reports_no_primary_stack(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")

    assert _primary_stack(tmp_path) is None
