"""Resolving the workflow template before anything is written, and the config-only plans.

The comment above `execute_init_plan`'s resolve step records a real bug: the workflow template
used to be resolved last, after the config and seven evidence files were already on disk, so a
packaging fault left the adopter with a half-initialised repository and an error naming a file
they never asked for. Resolving first makes `init` all-or-nothing for that failure, and the
test here holds it -- an unresolvable template must leave the target untouched.

Around it, the two ways the resolver can come up empty are different problems and say so: a
destination filename the kit does not ship a template for is bad input, while a template that
is named but missing from both the package and the repository checkout is a packaging fault.

`_kit_version` degrades to "unknown" rather than raising, because it only labels a generated
file's `generator:` field -- failing an `init` over a metadata lookup would be absurd.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application import init_writer as iw
from oss_policy_kit.domain.errors import InvalidInputError

# --------------------------------------------------------------------------- #
# Template resolution
# --------------------------------------------------------------------------- #


def test_every_shipped_destination_resolves_to_a_body() -> None:
    """The counterpart to the failure tests: the real templates must actually be there."""

    for dest in iw._WORKFLOW_SOURCE_BY_DEST:
        source, body = iw._resolve_workflow_template(dest)
        assert source
        assert body.strip()


def test_an_unknown_destination_filename_is_bad_input() -> None:
    """The message lists what is supported, so the caller can correct the flag."""

    with pytest.raises(InvalidInputError, match="Unknown workflow template"):
        iw._resolve_workflow_template("not-a-template.yml")


def test_a_template_missing_from_both_locations_is_a_packaging_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Different from bad input: the kit named a template it does not ship."""

    def _no_package(_name: str) -> object:
        raise ModuleNotFoundError("packaged data unavailable")

    monkeypatch.setattr(iw.resources, "files", _no_package)
    monkeypatch.setattr(iw, "_WORKFLOW_TEMPLATE_REPO_PATH", tmp_path / "nowhere")

    dest = next(iter(iw._WORKFLOW_SOURCE_BY_DEST))
    with pytest.raises(InvalidInputError, match="Workflow template not found"):
        iw._resolve_workflow_template(dest)


def test_the_repository_checkout_is_the_fallback_when_the_package_has_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Running from a source checkout must still find the template it ships."""

    def _no_package(_name: str) -> object:
        raise FileNotFoundError("packaged data unavailable")

    dest = next(iter(iw._WORKFLOW_SOURCE_BY_DEST))
    source_name = iw._WORKFLOW_SOURCE_BY_DEST[dest]
    (tmp_path / source_name).write_text("name: from-checkout\n", encoding="utf-8")

    monkeypatch.setattr(iw.resources, "files", _no_package)
    monkeypatch.setattr(iw, "_WORKFLOW_TEMPLATE_REPO_PATH", tmp_path)

    source, body = iw._resolve_workflow_template(dest)
    assert source == source_name
    assert "from-checkout" in body


# --------------------------------------------------------------------------- #
# Version label
# --------------------------------------------------------------------------- #


def test_an_unavailable_version_degrades_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """It labels a generated file; failing `init` over a metadata lookup would be absurd."""

    import importlib.metadata

    def _boom(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("oss-policy-kit")

    monkeypatch.setattr(importlib.metadata, "version", _boom)
    assert iw._kit_version() == "unknown"


def test_the_installed_version_is_used_when_available() -> None:
    assert iw._kit_version() != "unknown"


# --------------------------------------------------------------------------- #
# Plans that write only some of the files
# --------------------------------------------------------------------------- #


def _plan(target: Path, **overrides: object) -> object:
    from oss_policy_kit.application.init_planner import build_init_plan

    plan = build_init_plan(
        target=target,
        forced_profile="github-level-1",
        forced_platform="github",
        fail_on="fail",
        output_dir="out",
        with_waivers=False,
        with_evidence=False,
        with_workflow=False,
        force=False,
        dry_run=bool(overrides.get("dry_run", False)),
    )
    for key, value in overrides.items():
        object.__setattr__(plan, key, value)
    return plan


def test_a_plan_that_writes_no_config_writes_no_config_file(tmp_path: Path) -> None:
    """`write_config` is a real switch: with it off the file must not appear."""

    plan = _plan(tmp_path, write_config=False)
    iw.execute_init_plan(plan)  # type: ignore[arg-type]
    assert not (tmp_path / iw.CONFIG_FILENAME).exists()


def test_a_dry_run_that_writes_no_config_reports_no_config_action(tmp_path: Path) -> None:
    plan = _plan(tmp_path, dry_run=True, write_config=False)
    outcome = iw.execute_init_plan(plan)  # type: ignore[arg-type]
    assert not any(iw.CONFIG_FILENAME in str(p) for p in outcome.created)


def test_a_dry_run_with_a_config_reports_it(tmp_path: Path) -> None:
    """The counterpart, so the two tests above cannot pass on a writer that does nothing."""

    plan = _plan(tmp_path, dry_run=True)
    outcome = iw.execute_init_plan(plan)  # type: ignore[arg-type]
    assert any(iw.CONFIG_FILENAME in str(p) for p in outcome.created)
    assert not (tmp_path / iw.CONFIG_FILENAME).exists(), "a dry run wrote a file"


def test_an_unresolvable_template_leaves_the_target_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The bug this ordering fixed: config and evidence used to land before the template failed."""

    def _boom(_dest: str) -> tuple[str, str]:
        raise InvalidInputError("Workflow template not found: ci.yml")

    monkeypatch.setattr(iw, "_resolve_workflow_template", _boom)
    plan = _plan(tmp_path, write_workflow=True)

    with pytest.raises(InvalidInputError, match="Workflow template not found"):
        iw.execute_init_plan(plan)  # type: ignore[arg-type]

    assert not (tmp_path / iw.CONFIG_FILENAME).exists(), "config was written before the failure"
