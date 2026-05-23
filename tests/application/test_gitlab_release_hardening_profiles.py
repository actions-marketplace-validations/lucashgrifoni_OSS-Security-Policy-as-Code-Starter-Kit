"""gitlab-release-hardening-{1,2,3}: GitLab release track parity with github/azure/aws."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from oss_policy_kit.application.loader import bundled_kit_root, load_catalog, load_profile_by_id

_RH = ["gitlab-release-hardening-1", "gitlab-release-hardening-2", "gitlab-release-hardening-3"]


@pytest.mark.parametrize("pid", _RH)
def test_release_hardening_loads_and_controls_resolve(pid: str) -> None:
    spec = load_profile_by_id(bundled_kit_root(), pid)
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    assert spec.id == pid
    assert len(spec.control_ids) == len(set(spec.control_ids)), "duplicate control IDs"
    for cid in spec.control_ids:
        assert cid in catalog, f"Control '{cid}' missing from catalog."


def test_release_hardening_ladder_is_monotonic() -> None:
    rh1 = set(load_profile_by_id(bundled_kit_root(), "gitlab-release-hardening-1").control_ids)
    rh2 = set(load_profile_by_id(bundled_kit_root(), "gitlab-release-hardening-2").control_ids)
    rh3 = set(load_profile_by_id(bundled_kit_root(), "gitlab-release-hardening-3").control_ids)
    assert rh1.issubset(rh2), f"RH1 controls missing from RH2: {sorted(rh1 - rh2)}"
    assert rh2.issubset(rh3), f"RH2 controls missing from RH3: {sorted(rh2 - rh3)}"


def test_release_hardening_3_is_superset_of_level_3() -> None:
    l3 = set(load_profile_by_id(bundled_kit_root(), "gitlab-level-3").control_ids)
    rh3 = set(load_profile_by_id(bundled_kit_root(), "gitlab-release-hardening-3").control_ids)
    assert l3.issubset(rh3), f"release ladder broken: L3 controls missing from RH3: {sorted(l3 - rh3)}"


def test_release_hardening_1_extends_level_1_with_branch_evidence() -> None:
    l1 = set(load_profile_by_id(bundled_kit_root(), "gitlab-level-1").control_ids)
    rh1 = set(load_profile_by_id(bundled_kit_root(), "gitlab-release-hardening-1").control_ids)
    assert l1.issubset(rh1)
    assert "PLAT-BRPROT-015" in rh1 - l1


@pytest.mark.parametrize("pid", _RH)
def test_release_hardening_excludes_github_specific_controls(pid: str) -> None:
    controls = set(load_profile_by_id(bundled_kit_root(), pid).control_ids)
    assert not any(c.startswith("GH-PLAT-") for c in controls)
    assert "CI-WFCALLSHA-055" not in controls


@pytest.mark.parametrize("pid", _RH)
def test_release_hardening_listed_in_profiles_json_as_gitlab(pid: str) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "profiles", "--format", "json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    row = next((p for p in data["profiles"] if p["profile_id"] == pid), None)
    assert row is not None
    assert row["family"] == "gitlab"
    assert row["track"] == "rel"


def test_gitlab_family_has_full_ladder_and_release_track() -> None:
    """GitLab now mirrors github/azure/aws: 3 ladder + 3 release-hardening profiles."""
    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "profiles", "--format", "json", "--family", "gitlab"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert proc.returncode == 0
    ids = {p["profile_id"] for p in json.loads(proc.stdout)["profiles"]}
    assert ids == {
        "gitlab-level-1",
        "gitlab-level-2",
        "gitlab-level-3",
        "gitlab-release-hardening-1",
        "gitlab-release-hardening-2",
        "gitlab-release-hardening-3",
    }
