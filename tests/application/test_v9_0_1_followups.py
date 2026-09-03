"""Regression tests for the v9.0.1 fast-follow fixes (application layer).

These lock the behaviour fixed after the v9.0.0 published-wheel end-user validation:

- M1/M2: a blank ``--report-json-contract`` value fails closed (LoadError) instead of
  silently mapping to the default ``reports/2.0`` contract.
- L6: the unknown-profile error reports a repo-relative path, never the absolute
  install/site-packages location (which leaked the OS username).
- L4: ``--with-evidence`` on a platform with no evidence templates (gitlab/unknown) is
  honestly downgraded with a note instead of being silently dropped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.application import loader
from oss_policy_kit.application.engine import (
    REPORT_JSON_SCHEMA_URL_V2_0,
    report_json_schema_url,
)
from oss_policy_kit.application.init_planner import build_init_plan
from oss_policy_kit.domain.errors import LoadError

# --------------------------------------------------------------------------- #
# M1/M2 — blank report contract fails closed (no silent fallback to the default)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("blank", ["", "   ", "\t", "  \n "])
def test_report_contract_blank_is_rejected(blank: str) -> None:
    with pytest.raises(LoadError):
        report_json_schema_url(blank)


@pytest.mark.parametrize("ok", ["2.0", "v2.0", "V2.0", "  2.0  ", "2.0\n"])
def test_report_contract_two_zero_accepted(ok: str) -> None:
    assert report_json_schema_url(ok) == REPORT_JSON_SCHEMA_URL_V2_0


@pytest.mark.parametrize("removed", ["1.0", "0.3", "0.2", "0.1", "banana", "3.0", "2"])
def test_report_contract_other_values_rejected(removed: str) -> None:
    with pytest.raises(LoadError):
        report_json_schema_url(removed)


# --------------------------------------------------------------------------- #
# L6 — unknown-profile error never leaks the absolute install path
# --------------------------------------------------------------------------- #


def test_unknown_profile_message_is_path_sanitized(tmp_path: Path) -> None:
    with pytest.raises(LoadError) as exc:
        loader.resolve_profile_file(tmp_path, "no-such-profile")
    msg = str(exc.value)
    assert "Unknown profile 'no-such-profile'" in msg
    assert "data/profiles/no-such-profile/profile.yaml" in msg
    # The absolute kit_root must NOT appear (no site-packages / OS-username leak).
    assert str(tmp_path) not in msg


def test_unknown_profile_yaml_ref_message(tmp_path: Path) -> None:
    with pytest.raises(LoadError) as exc:
        loader.resolve_profile_file(tmp_path, "missing-profile.yaml")
    msg = str(exc.value)
    assert "Profile file not found" in msg
    assert str(tmp_path) not in msg
    # No confusing "<id>.yaml/profile.yaml" double-suffix.
    assert ".yaml/profile.yaml" not in msg


# --------------------------------------------------------------------------- #
# L4 — --with-evidence honestly downgraded (with a note) on non-scaffoldable platforms
# --------------------------------------------------------------------------- #


def _build(target: Path, **kw: object) -> object:
    defaults: dict[str, object] = dict(
        forced_profile=None,
        forced_platform=None,
        fail_on="fail",
        output_dir="out",
        with_waivers=False,
        with_evidence=True,
        with_workflow=False,
        force=False,
        dry_run=False,
    )
    defaults.update(kw)
    return build_init_plan(target=target, **defaults)  # type: ignore[arg-type]


def test_init_plan_with_evidence_unknown_platform_downgrades(tmp_path: Path) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    plan = _build(repo)
    assert plan.platform == "unknown"  # type: ignore[attr-defined]
    assert plan.scaffold_evidence is False  # type: ignore[attr-defined]
    # The drop is surfaced as a note (so it is visible in human output AND --format json).
    assert any("with-evidence" in n for n in plan.notes)  # type: ignore[attr-defined]


def test_init_plan_with_evidence_github_scaffolds(tmp_path: Path) -> None:
    repo = tmp_path / "gh"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    plan = _build(repo)
    assert plan.platform == "github"  # type: ignore[attr-defined]
    assert plan.scaffold_evidence is True  # type: ignore[attr-defined]
    # No spurious downgrade note when evidence IS scaffolded.
    assert not any("skipped --with-evidence" in n for n in plan.notes)  # type: ignore[attr-defined]
