"""The GitLab suggestion ladder and the path-collection edges of `recommend-profile`.

`recommend-profile` decides which profile a newcomer is told to start from. Its GitHub
branch is well covered; the GitLab branch that mirrors it was not executed at all, nor
were the guards that stop `_workflow_yaml_paths` from reporting a file outside the target.

That second one matters beyond coverage: the resolve-and-contain check exists so a symlink
in `.github/workflows/` cannot make the tool read, and then report on, a file the operator
never pointed it at. It had no test.

Everything here calls the helpers directly. The suggestion builders are pure functions over
lists of paths, so the ladder can be pinned exactly -- which rung, at which rank, justified
by which signals -- without constructing a repository for each combination.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import profile_hints as ph


def _ids(rows: list[tuple[int, str, str, list[str]]]) -> list[str]:
    return [profile for _rank, profile, _why, _based_on in rows]


def _row(rows: list[tuple[int, str, str, list[str]]], profile: str) -> tuple[int, str, str, list[str]]:
    matches = [r for r in rows if r[1] == profile]
    assert len(matches) == 1, f"expected exactly one {profile} row, got {len(matches)}"
    return matches[0]


# --------------------------------------------------------------------------- #
# the GitLab ladder
# --------------------------------------------------------------------------- #


def test_ci_and_evidence_together_reach_release_hardening_2(tmp_path: Path) -> None:
    """Both signals are required: the rung exists to check declared release posture."""

    rows = ph._suggestions_gitlab(
        gl_paths=[tmp_path / ".gitlab-ci.yml"],
        gitlab_ev=[tmp_path / "gitlab-release.json"],
        wf_paths=[],
        az_paths=[],
        buildspec=False,
        empty_evidence_dir=False,
    )

    rank, _profile, why, based_on = _row(rows, "gitlab-release-hardening-2")
    assert rank == 300
    assert based_on == ["gitlab_ci_yaml", "gitlab_evidence_json_files"]
    assert "not templates" in why


def test_empty_evidence_dir_with_pipelines_only_reaches_hardening_1(tmp_path: Path) -> None:
    """Without evidence there is nothing to verify, so the ladder starts one rung lower."""

    rows = ph._suggestions_gitlab(
        gl_paths=[tmp_path / ".gitlab-ci.yml"],
        gitlab_ev=[],
        wf_paths=[],
        az_paths=[],
        buildspec=False,
        empty_evidence_dir=True,
    )

    rank, _profile, _why, based_on = _row(rows, "gitlab-release-hardening-1")
    assert rank == 290
    assert based_on == ["evidence_dir_empty", "gitlab_ci_yaml"]
    assert "gitlab-release-hardening-2" not in _ids(rows)


@pytest.mark.parametrize(("count", "expected"), [(1, "gitlab-level-1"), (2, "gitlab-level-2"), (5, "gitlab-level-2")])
def test_pipeline_count_picks_the_tier(tmp_path: Path, count: int, expected: str) -> None:
    """Two or more pipeline files is the documented threshold for level 2."""

    rows = ph._suggestions_gitlab(
        gl_paths=[tmp_path / f"ci-{i}.yml" for i in range(count)],
        gitlab_ev=[],
        wf_paths=[],
        az_paths=[],
        buildspec=False,
        empty_evidence_dir=False,
    )

    assert expected in _ids(rows)


def test_gitlab_evidence_without_any_ci_is_only_a_weak_fallback(tmp_path: Path) -> None:
    """Evidence alone is a hint, not a pipeline; it must rank below a real CI signal."""

    rows = ph._suggestions_gitlab(
        gl_paths=[],
        gitlab_ev=[tmp_path / "gitlab-release.json"],
        wf_paths=[],
        az_paths=[],
        buildspec=False,
        empty_evidence_dir=False,
    )

    rank, _profile, _why, _based_on = _row(rows, "gitlab-level-1")
    assert rank == 150


@pytest.mark.parametrize("competitor", ["wf_paths", "az_paths", "buildspec"])
def test_another_platforms_ci_suppresses_the_gitlab_fallback(tmp_path: Path, competitor: str) -> None:
    """GitLab evidence beside GitHub/Azure/AWS CI is a leftover, not the platform in use."""

    kwargs: dict[str, Any] = {"wf_paths": [], "az_paths": [], "buildspec": False}
    kwargs[competitor] = True if competitor == "buildspec" else [tmp_path / "other"]

    rows = ph._suggestions_gitlab(
        gl_paths=[],
        gitlab_ev=[tmp_path / "gitlab-release.json"],
        empty_evidence_dir=False,
        **kwargs,
    )

    assert rows == []


# --------------------------------------------------------------------------- #
# every platform's release-hardening-2 justification
# --------------------------------------------------------------------------- #


def test_release_hardening_2_names_both_signals_on_every_platform(tmp_path: Path) -> None:
    """The rung is only offered when both signals are present, so both must be cited.

    This is the whole reachable space of that justification: `can_rh2` is
    `bool(ci) and bool(evidence)`, so there is exactly one state in which the row is
    emitted at all. Anything the code does for a partial signal set is unreachable from
    here -- which is why the per-platform probe and normalizer helpers were removed
    rather than tested through a hand-built state the caller cannot produce.
    """

    ci = [tmp_path / "ci"]
    ev = [tmp_path / "ev.json"]

    gh: list[tuple[int, str, str, list[str]]] = []
    ph._append_gh_release_hardening(gh, can_rh2=True, can_rh1=False, wf_paths=ci, github_ev=ev)

    cases = {
        "github-release-hardening-2": (
            _row(gh, "github-release-hardening-2"),
            ["github_actions_workflows", "github_evidence_json_files"],
        ),
        "gitlab-release-hardening-2": (
            _row(
                ph._suggestions_gitlab(
                    gl_paths=ci, gitlab_ev=ev, wf_paths=[], az_paths=[], buildspec=False, empty_evidence_dir=False
                ),
                "gitlab-release-hardening-2",
            ),
            ["gitlab_ci_yaml", "gitlab_evidence_json_files"],
        ),
        "azure-release-hardening-2": (
            _row(
                ph._suggestions_azure(az_paths=ci, azure_ev=ev, wf_paths=[], buildspec=False, empty_evidence_dir=False),
                "azure-release-hardening-2",
            ),
            ["azure_pipelines_yaml", "azure_evidence_json_files"],
        ),
        "aws-release-hardening-2": (
            _row(
                ph._suggestions_aws(buildspec=True, aws_ev=ev, wf_paths=[], az_paths=[], empty_evidence_dir=False),
                "aws-release-hardening-2",
            ),
            ["aws_codebuild_buildspec", "aws_evidence_json_files"],
        ),
    }
    for profile, (row, expected) in cases.items():
        assert row[3] == expected, f"{profile} cited {row[3]}"


# --------------------------------------------------------------------------- #
# path collection guards
# --------------------------------------------------------------------------- #


def test_workflow_paths_ignores_a_directory_named_like_a_workflow(tmp_path: Path) -> None:
    """`*.yml` also matches a directory; treating one as a workflow would break parsing."""

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "real.yml").write_text("on: push\n", encoding="utf-8")
    (wf / "decoy.yml.d").mkdir()
    (wf / "notayml.yaml").mkdir()

    found = ph._workflow_yaml_paths(tmp_path)

    assert [p.name for p in found] == ["real.yml"]


def test_workflow_paths_skips_an_entry_that_cannot_be_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A path the OS refuses to resolve is dropped, not fatal to the whole recommendation."""

    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("on: push\n", encoding="utf-8")
    assert ph._workflow_yaml_paths(tmp_path), "fixture does not reach the branch under test"

    real = Path.resolve

    def _resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        if self.name == "ci.yml":
            raise OSError(5, "I/O error")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _resolve)

    assert ph._workflow_yaml_paths(tmp_path) == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs elevation on Windows")
def test_a_symlink_out_of_the_target_is_not_reported_as_a_workflow(tmp_path: Path) -> None:
    """The guard exists so a link cannot make the tool report on a file outside --target."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.yml").write_text("on: push\n", encoding="utf-8")
    target = tmp_path / "repo"
    wf = target / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "escape.yml").symlink_to(outside / "secret.yml")

    assert ph._workflow_yaml_paths(target) == []


def test_gitlab_ci_paths_finds_both_locations_without_duplicating(tmp_path: Path) -> None:
    """Root and `.gitlab/` are both valid homes; the same file must not be counted twice."""

    (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n", encoding="utf-8")
    (tmp_path / ".gitlab").mkdir()
    (tmp_path / ".gitlab" / ".gitlab-ci.yaml").write_text("stages: []\n", encoding="utf-8")

    found = ph._gitlab_ci_paths(tmp_path)

    assert len(found) == len(set(found)) == 2


# --------------------------------------------------------------------------- #
# stack detection fallbacks
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("marker", "signal"),
    [("requirements.txt", "python_requirements"), ("setup.py", "python_setup"), ("setup.cfg", "python_setup")],
)
def test_python_is_detected_without_a_pyproject(tmp_path: Path, marker: str, signal: str) -> None:
    """Not every Python project has migrated to pyproject.toml."""

    (tmp_path / marker).write_text("", encoding="utf-8")
    found: list[dict[str, str]] = []
    weights: dict[str, int] = {}

    label = ph._detect_python_stack(tmp_path, found, [], weights)

    assert label == ph._LABEL_PYTHON
    assert signal in {s["id"] for s in found}
    assert weights[ph._LABEL_PYTHON] > 0


def test_a_bare_requirements_txt_weighs_less_than_a_declared_project(tmp_path: Path) -> None:
    """A vendored requirements.txt beside another stack must not outrank that stack.

    Separate directories on purpose: the markers are checked in order and requirements.txt
    comes first, so a repo holding both is scored as the sidecar. What is asserted here is
    the weight each marker carries on its own, which is what the ranking compares.
    """

    sidecar_repo = tmp_path / "pinned-deps-only"
    sidecar_repo.mkdir()
    (sidecar_repo / "requirements.txt").write_text("", encoding="utf-8")
    sidecar: dict[str, int] = {}
    ph._detect_python_stack(sidecar_repo, [], [], sidecar)

    declared_repo = tmp_path / "declared-project"
    declared_repo.mkdir()
    (declared_repo / "setup.py").write_text("", encoding="utf-8")
    declared: dict[str, int] = {}
    ph._detect_python_stack(declared_repo, [], [], declared)

    assert sidecar[ph._LABEL_PYTHON] < declared[ph._LABEL_PYTHON]


def test_unreadable_pyproject_yields_no_tooling_notes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The stack was identified by the file existing; the notes are advisory."""

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.ruff]\n[tool.mypy]\n", encoding="utf-8")
    baseline: list[str] = []
    ph._append_pyproject_tooling_notes(pyproject, baseline)
    assert len(baseline) == 2, "fixture does not reach the branch under test"

    real = Path.read_text

    def _read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == "pyproject.toml":
            raise OSError(13, "Permission denied")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _read_text)
    notes: list[str] = []

    ph._append_pyproject_tooling_notes(pyproject, notes)

    assert notes == []


@pytest.mark.parametrize("marker", ["App.csproj", "Solution.sln"])
def test_dotnet_is_detected_by_glob_not_by_a_fixed_filename(tmp_path: Path, marker: str) -> None:
    """.NET projects name these after the project, so only a glob can find them."""

    (tmp_path / marker).write_text("", encoding="utf-8")
    found: list[dict[str, str]] = []
    weights: dict[str, int] = {}

    primary = ph._detect_simple_stacks(tmp_path, found, None, weights)

    assert primary == ph._LABEL_DOTNET
    assert "dotnet_csproj" in {s["id"] for s in found}


def test_an_earlier_stack_keeps_primary_when_dotnet_is_also_present(tmp_path: Path) -> None:
    """`primary` is first-wins; .NET must not steal it from an already-detected stack."""

    (tmp_path / "App.csproj").write_text("", encoding="utf-8")

    primary = ph._detect_simple_stacks(tmp_path, [], ph._LABEL_GO, {})

    assert primary == ph._LABEL_GO


# --------------------------------------------------------------------------- #
# serialization
# --------------------------------------------------------------------------- #


def test_recommendation_serializes_to_plain_json_types(tmp_path: Path) -> None:
    """`--format json` must not emit a dataclass repr; nested structures have to survive."""

    import json

    payload = ph.build_profile_recommendation(tmp_path).to_json_dict()

    assert json.loads(json.dumps(payload)) == payload
    assert "schema_version" in payload


def test_schema_backed_filenames_degrade_to_empty_on_an_unusual_layout(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unreadable schema package must not make every evidence file "unrecognized".

    The caller falls back to a static floor; returning a partial set here would silently
    downgrade real evidence instead.
    """

    def _boom(_package: object) -> object:
        raise ModuleNotFoundError("no such package")

    monkeypatch.setattr(ph.ir, "files", _boom)

    assert ph.schema_backed_evidence_filenames() == frozenset()


def test_schema_backed_filenames_finds_the_bundled_schemas() -> None:
    """The negative case above only means something if the normal path still works."""

    names = ph.schema_backed_evidence_filenames()

    assert names, "no bundled evidence schemas were discovered"
    assert all(n.endswith(".json") for n in names)
