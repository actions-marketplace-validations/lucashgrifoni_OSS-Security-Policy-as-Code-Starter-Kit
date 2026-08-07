"""The workflow templates must ship inside the wheel, not just exist in the repo.

`init --with-workflow` is the second half of the quickstart at README.md:39 and
docs/tutorial-first-pr-gate.md:21. It exited 2 on every real install --

    Error: Workflow template not found: github-oss-policy-check.yml.
           Expected under packaged data or templates\\workflows/.

-- because `pyproject.toml` packaged `data/**/*.yaml` and `data/**/*.json` while the
templates are `.yml`, and they lived at the repository root rather than under `src/`.
The wheel contained no templates at all.

**The suite passed the whole time.** `_resolve_workflow_template` falls back to the
CWD-relative `templates/workflows/`, and pytest runs from the repo root, where that
directory exists. The test environment supplied what the artifact was missing, so the
packaging fault was invisible to every test that could have caught it.

That is why the test below changes directory out of the repository first. Run from the
repo root it would pass with the packaging reverted, which is exactly the failure it
exists to prevent.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from tests.conftest import ROOT

from oss_policy_kit.application.init_planner import InitPlan
from oss_policy_kit.application.init_writer import (
    _WORKFLOW_SOURCE_BY_DEST,
    _resolve_workflow_template,
    execute_init_plan,
)
from oss_policy_kit.domain.errors import InvalidInputError

_REPO_TEMPLATES = ROOT / "templates" / "workflows"
_PACKAGED_TEMPLATES = ROOT / "src" / "oss_policy_kit" / "data" / "templates" / "workflows"


@pytest.mark.parametrize("dest", sorted(_WORKFLOW_SOURCE_BY_DEST))
def test_template_resolves_with_no_repository_on_disk(
    dest: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolution must come from the package, with the CWD fallback out of reach.

    ``monkeypatch.chdir`` is the whole test: it removes the ``templates/workflows/``
    directory from the resolver's reach, leaving only the packaged copy. An installed
    wheel is always in this position.
    """

    monkeypatch.chdir(tmp_path)
    assert not (Path.cwd() / "templates" / "workflows").exists(), "fixture still sees the repo fallback"

    source, body = _resolve_workflow_template(dest)

    assert source == _WORKFLOW_SOURCE_BY_DEST[dest]
    assert body.strip(), "template resolved to an empty body"
    assert "oss-policy-kit" in body


def _text_without_eol(path: Path) -> list[str]:
    """Return the file's lines with the line terminator discarded.

    Content equality is the property these copies must hold; the byte used to end a line
    is not part of it. Comparing raw bytes made the verdict depend on the checkout instead:
    `.gitattributes` declares `*.yml text eol=lf` and both blobs are LF in the repository,
    but a Windows working tree carried over from an older checkout keeps CRLF in
    `templates/workflows/` while `src/` holds LF. The assertion then failed on every local
    run and passed in CI, where the clone is fresh -- the same environment-dependent verdict
    this suite keeps having to remove.
    """

    return path.read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize("dest", sorted(_WORKFLOW_SOURCE_BY_DEST))
def test_packaged_copy_matches_the_adopter_facing_copy(dest: str) -> None:
    """The two copies must not drift.

    `templates/workflows/` stays at the repository root because eight documents link to
    it and adopters read it on GitHub; the packaged copy under `src/` is what ships. Two
    files, one meaning -- so this compares them line for line rather than trusting that
    whoever edits one remembers the other.
    """

    source = _WORKFLOW_SOURCE_BY_DEST[dest]
    packaged = _PACKAGED_TEMPLATES / source
    adopter_facing = _REPO_TEMPLATES / source

    assert packaged.is_file(), f"{source} is missing from the packaged templates"
    assert adopter_facing.is_file(), f"{source} is missing from templates/workflows/"
    assert _text_without_eol(packaged) == _text_without_eol(adopter_facing), (
        f"{source} differs between the packaged copy and templates/workflows/ -- "
        "edit both, or the wheel ships something the documentation does not describe"
    )


@pytest.mark.parametrize("dest", sorted(_WORKFLOW_SOURCE_BY_DEST))
def test_packaged_template_has_no_carriage_returns(dest: str) -> None:
    """The shipped copy is LF, whatever the working tree looks like.

    Dropping the terminator above answers "did the content drift"; it cannot answer "does
    the wheel ship CRLF". That second question still matters -- the templates land in a
    consumer's `.github/workflows/` -- so it gets its own assertion against the packaged
    copy alone, which is the file that actually ships.
    """

    packaged = _PACKAGED_TEMPLATES / _WORKFLOW_SOURCE_BY_DEST[dest]

    assert b"\r\n" not in packaged.read_bytes(), (
        f"{packaged.name} carries CRLF in the packaged copy; `.gitattributes` declares "
        "`*.yml text eol=lf`, so this means the file was staged with the attribute bypassed"
    )


def test_every_referenced_template_is_packaged() -> None:
    """Whatever `_WORKFLOW_SOURCE_BY_DEST` promises, the package must contain.

    Adding a destination without staging its template is the same defect again, one
    filename further along.
    """

    missing = [src for src in _WORKFLOW_SOURCE_BY_DEST.values() if not (_PACKAGED_TEMPLATES / src).is_file()]

    assert not missing, f"referenced but not packaged: {missing}"


def test_init_writes_nothing_when_the_template_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A packaging fault must not leave the adopter with a half-initialised repository.

    Before the template was resolved up front, `init --with-workflow` wrote the config
    and seven evidence files, then failed on the workflow -- an error naming a file the
    adopter never typed, on top of a repo that was already modified.
    """

    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.setattr(
        "oss_policy_kit.application.init_writer._WORKFLOW_SOURCE_BY_DEST",
        {"oss-policy-check.yml": "does-not-exist.yml"},
    )
    monkeypatch.chdir(tmp_path)

    plan = InitPlan(
        target=target,
        platform="github",
        primary_stack="Python",
        signals=["github_actions_workflows"],
        profile="github-level-1",
        profile_source="recommended",
        fail_on="fail",
        output_dir="out",
        write_config=True,
        write_waivers=True,
        scaffold_evidence=True,
        write_workflow=True,
        workflow_filename="oss-policy-check.yml",
        force=False,
        dry_run=False,
    )

    with pytest.raises(InvalidInputError):
        execute_init_plan(plan)

    leftovers = sorted(p.name for p in target.rglob("*") if p.is_file())
    assert not leftovers, f"init left files behind after failing: {leftovers}"


def test_packaged_templates_are_not_shadowed_by_the_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A `templates/workflows/` in the adopter's own repo must not win over the package.

    The fallback exists for running from a source checkout. It must stay a fallback: a
    repository that happens to contain that path would otherwise silently substitute its
    own file for the one the kit ships.
    """

    decoy_dir = tmp_path / "templates" / "workflows"
    decoy_dir.mkdir(parents=True)
    (decoy_dir / "github-oss-policy-check.yml").write_text("name: DECOY\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    _, body = _resolve_workflow_template("oss-policy-check.yml")

    assert "DECOY" not in body, "the current directory shadowed the packaged template"


def test_env_matches_what_an_installed_wheel_sees() -> None:
    """Guard on the guard: prove the packaged path is real, not a leftover build dir."""

    assert _PACKAGED_TEMPLATES.is_dir(), "src/oss_policy_kit/data/templates/workflows/ is missing"
    staged = sorted(p.name for p in _PACKAGED_TEMPLATES.glob("*.yml"))
    assert staged, "no .yml templates staged under the package"
    assert os.path.commonpath([_PACKAGED_TEMPLATES, ROOT / "src"]) == str(ROOT / "src"), (
        "packaged templates must live under src/ to be picked up by package-data"
    )
