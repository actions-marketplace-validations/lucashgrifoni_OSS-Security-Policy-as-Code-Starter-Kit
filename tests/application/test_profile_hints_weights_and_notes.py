"""Stack weighting, signal ranking, and the notes that explain a thin recommendation.

`recommend-profile` ranks the stacks it detects, and the weight decides which one leads. The
distinction the weights encode is worth protecting: a `package.json` with a lockfile is a
project, the same file without one may be a tooling or docs sidecar, and treating the second
like the first makes the kit recommend a Node profile for a repository that merely has a
`package.json` next to its docs.

The notes are the other half. A recommendation with almost nothing behind it has to say so --
an empty evidence directory with no CI signals, or evidence files whose names the kit does not
recognise. Silence there reads as "we looked and everything is fine", which is the opposite of
what happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application import profile_hints as ph
from oss_policy_kit.application.profile_hints import build_profile_recommendation


def _note_text(rec: object) -> str:
    return " ".join(str(n) for n in getattr(rec, "notes", []))


def _signal_ids(rec: object) -> list[str]:
    return [str(s["id"]) for s in getattr(rec, "signals_detected", [])]


# --------------------------------------------------------------------------- #
# Stack weights
# --------------------------------------------------------------------------- #


def test_a_node_project_with_a_lockfile_outweighs_one_without(tmp_path: Path) -> None:
    """A lockfile is what separates a real project from a docs sidecar."""

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    with_lock: dict[str, int] = {}
    ph._detect_node_stack(tmp_path, [], with_lock)

    (tmp_path / "package-lock.json").unlink()
    without_lock: dict[str, int] = {}
    ph._detect_node_stack(tmp_path, [], without_lock)

    assert with_lock[ph._LABEL_NODE] > without_lock[ph._LABEL_NODE]


def test_a_python_project_is_weighted_when_weights_are_requested(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    weights: dict[str, int] = {}
    ph._detect_python_stack(tmp_path, [], [], weights)
    assert weights, "a detected Python project recorded no weight"


@pytest.mark.parametrize("marker", ["go.mod", "Cargo.toml", "pom.xml"])
def test_a_single_file_language_marker_is_weighted(marker: str, tmp_path: Path) -> None:
    (tmp_path / marker).write_text("x", encoding="utf-8")
    weights: dict[str, int] = {}
    ph._detect_simple_stacks(tmp_path, [], None, weights)
    assert weights, f"{marker} recorded no weight"


def test_a_dotnet_project_is_weighted(tmp_path: Path) -> None:
    (tmp_path / "App.csproj").write_text("<Project/>", encoding="utf-8")
    weights: dict[str, int] = {}
    ph._detect_simple_stacks(tmp_path, [], None, weights)
    assert weights.get(ph._LABEL_DOTNET), weights


def test_detectors_work_without_a_weights_dict(tmp_path: Path) -> None:
    """The weights argument is optional; callers that only want signals must not break."""

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    assert ph._detect_node_stack(tmp_path, []) == ph._LABEL_NODE


# --------------------------------------------------------------------------- #
# Signal ranking
# --------------------------------------------------------------------------- #


def test_a_qualifier_signal_sorts_beside_its_own_stack_not_at_the_end() -> None:
    """`node_lockfile` qualifies Node; it must follow the Node signal, not drift to the tail."""

    found = [
        {"id": "python_pyproject", "detail": "py"},
        {"id": "node_lockfile", "detail": "lock"},
        {"id": "node_js", "detail": "node"},
    ]
    weights = {ph._LABEL_NODE: 2, "Python": 1}
    ranked = ph._stack_evidence_order(found, weights)
    ids = [s["id"] for s in ranked]
    assert ids.index("node_lockfile") == ids.index("node_js") + 1, ids


def test_a_signal_that_is_not_a_stack_marker_sorts_last() -> None:
    """An unrelated signal must not be ranked as if it named a stack."""

    found = [
        {"id": "some_unrelated_signal", "detail": "x"},
        {"id": "node_js", "detail": "node"},
    ]
    ranked = ph._stack_evidence_order(found, {ph._LABEL_NODE: 2})
    assert [s["id"] for s in ranked][-1] == "some_unrelated_signal"


# --------------------------------------------------------------------------- #
# CI signals
# --------------------------------------------------------------------------- #


def test_a_gitlab_pipeline_is_reported_as_a_signal(tmp_path: Path) -> None:
    (tmp_path / ".gitlab-ci.yml").write_text("build:\n  script: echo hi\n", encoding="utf-8")
    rec = build_profile_recommendation(tmp_path)
    assert "gitlab_ci_yaml" in _signal_ids(rec), _signal_ids(rec)


def test_azure_pipeline_paths_never_repeat_a_file(tmp_path: Path) -> None:
    """The de-duplication guard cannot currently fire, and this pins why.

    The six globs are disjoint by directory and extension, so no file matches two of them --
    checked by materialising one file per pattern and intersecting the matches. The `seen` set
    is therefore dead today, and is left in place because the pattern list is data: adding an
    overlapping glob would make it live again, and the alternative is a duplicated path in the
    evidence list.
    """

    (tmp_path / "azure-pipelines.yml").write_text("jobs: []\n", encoding="utf-8")
    paths = ph._azure_pipeline_paths(tmp_path)
    assert len(paths) == len(set(paths)), paths
    assert len(paths) == 1, paths


# --------------------------------------------------------------------------- #
# Notes that admit a thin result
# --------------------------------------------------------------------------- #


def test_an_empty_evidence_directory_without_ci_is_called_out(tmp_path: Path) -> None:
    """Otherwise the run looks like it found a healthy repository with nothing to say."""

    (tmp_path / ".oss-policy-kit" / "evidence").mkdir(parents=True)
    rec = build_profile_recommendation(tmp_path)
    assert "empty .oss-policy-kit/evidence/" in _note_text(rec), _note_text(rec)


def test_an_evidence_directory_with_files_is_not_called_empty(tmp_path: Path) -> None:
    """The counterpart, so the note cannot fire on every repository."""

    ev = tmp_path / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True)
    (ev / "github-rulesets.json").write_text("{}", encoding="utf-8")
    assert "empty .oss-policy-kit/evidence/" not in _note_text(build_profile_recommendation(tmp_path))


def test_workflows_beside_an_empty_evidence_directory_suggest_the_first_rung(tmp_path: Path) -> None:
    """CI exists but nothing is attested yet: release-hardening-1 is the starting ladder."""

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n", encoding="utf-8")
    (tmp_path / ".oss-policy-kit" / "evidence").mkdir(parents=True)

    rec = build_profile_recommendation(tmp_path)
    ids = [str(s["profile_id"]) for s in rec.suggestions]
    assert "github-release-hardening-1" in ids, ids


def test_the_python_detector_also_works_without_a_weights_dict(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert ph._detect_python_stack(tmp_path, [], []) is not None


def test_a_workflow_symlinked_outside_the_target_is_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A symlink escaping --target would leak signals from a directory nobody asked about."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.yml").write_text("name: ci\non: push\n", encoding="utf-8")

    repo = tmp_path / "repo"
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "escape.yml").write_text("name: ci\non: push\n", encoding="utf-8")

    real_resolve = Path.resolve

    def _resolve(self: Path, *args: object, **kwargs: object) -> Path:
        if self.name == "escape.yml":
            return outside / "real.yml"
        return real_resolve(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", _resolve)
    assert ph._workflow_yaml_paths(repo) == []


def test_a_workflow_inside_the_target_is_read(tmp_path: Path) -> None:
    """The counterpart, so the guard above cannot pass by rejecting everything."""

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: ci\non: push\n", encoding="utf-8")
    assert len(ph._workflow_yaml_paths(tmp_path)) == 1


def test_requirements_txt_alone_is_weighted_as_a_possible_sidecar(tmp_path: Path) -> None:
    """A vendored requirements.txt beside another stack is not a Python project declaration."""

    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    weights: dict[str, int] = {}
    ph._detect_python_stack(tmp_path, [], [], weights)
    assert weights[ph._LABEL_PYTHON] == ph._STACK_WEIGHT_MAY_BE_SIDECAR

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname='x'\n", encoding="utf-8")
    declared: dict[str, int] = {}
    ph._detect_python_stack(tmp_path, [], [], declared)
    assert declared[ph._LABEL_PYTHON] > weights[ph._LABEL_PYTHON]


def test_requirements_txt_is_detected_without_a_weights_dict(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    assert ph._detect_python_stack(tmp_path, [], []) == ph._LABEL_PYTHON
