"""Unit tests for the catalog diff computation (T1.4, single source of truth)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from oss_policy_kit.application.catalog_diff import diff_catalogs, load_snapshot, render_human
from oss_policy_kit.domain.errors import InvalidInputError

_CTRL_A = {"id": "A", "title": "Control A", "category": "governance", "automation": "automated", "assurance": "signal"}
_CTRL_B = {"id": "B", "title": "Control B", "category": "ci", "automation": "automated", "assurance": "deterministic"}


def _write_kit(root: Path, controls: list[dict[str, Any]], profiles: dict[str, list[str]]) -> Path:
    (root / "controls").mkdir(parents=True, exist_ok=True)
    (root / "controls" / "catalog.yaml").write_text(yaml.safe_dump({"controls": controls}), encoding="utf-8")
    profiles_dir = root / "profiles"
    profiles_dir.mkdir(exist_ok=True)
    for pid, control_ids in profiles.items():
        pdir = profiles_dir / pid
        pdir.mkdir(exist_ok=True)
        (pdir / "profile.yaml").write_text(
            yaml.safe_dump({"id": pid, "title": pid, "controls": control_ids}), encoding="utf-8"
        )
    return root


def _old_and_new(tmp_path: Path) -> tuple[Path, Path]:
    old = _write_kit(
        tmp_path / "old",
        controls=[
            dict(_CTRL_A),
            dict(_CTRL_B),
            {"id": "C", "title": "Old C", "category": "release", "automation": "manual", "assurance": "signal"},
        ],
        profiles={"p1": ["A", "B"], "p2": ["A"]},
    )
    new = _write_kit(
        tmp_path / "new",
        controls=[
            dict(_CTRL_A),
            # C: title + assurance changed; D added; B removed.
            {
                "id": "C",
                "title": "New C",
                "category": "release",
                "automation": "manual",
                "assurance": "evidence-backed",
            },
            {
                "id": "D",
                "title": "Control D",
                "category": "governance",
                "automation": "automated",
                "assurance": "signal",
            },
        ],
        profiles={"p1": ["A", "C"], "p3": ["A"]},
    )
    return old, new


def test_added_removed_changed_controls(tmp_path: Path) -> None:
    old, new = _old_and_new(tmp_path)
    diff = diff_catalogs(load_snapshot(old, label="old"), load_snapshot(new, label="new"))

    assert [r.id for r in diff.added_controls] == ["D"]
    assert [r.id for r in diff.removed_controls] == ["B"]
    assert [c.id for c in diff.changed_controls] == ["C"]
    changed_fields = {fc.field: (fc.old, fc.new) for fc in diff.changed_controls[0].changes}
    assert changed_fields["title"] == ("Old C", "New C")
    assert changed_fields["assurance"] == ("signal", "evidence-backed")
    assert "category" not in changed_fields  # unchanged field is not reported


def test_profile_membership_delta(tmp_path: Path) -> None:
    old, new = _old_and_new(tmp_path)
    diff = diff_catalogs(load_snapshot(old, label="old"), load_snapshot(new, label="new"))

    assert diff.profiles_compared is True
    assert diff.added_profiles == ("p3",)
    assert diff.removed_profiles == ("p2",)
    assert [p.id for p in diff.changed_profiles] == ["p1"]
    p1 = diff.changed_profiles[0]
    assert p1.added == ("C",)
    assert p1.removed == ("B",)


def test_identical_snapshots_is_empty(tmp_path: Path) -> None:
    old, _ = _old_and_new(tmp_path)
    diff = diff_catalogs(load_snapshot(old, label="a"), load_snapshot(old, label="b"))
    assert diff.is_empty is True
    assert "No control or profile differences." in render_human(diff)


def test_bare_catalog_yaml_skips_profiles(tmp_path: Path) -> None:
    old, new = _old_and_new(tmp_path)
    # Point --from at a standalone catalog.yaml with no sibling profiles/ dir.
    standalone = tmp_path / "loose" / "catalog.yaml"
    standalone.parent.mkdir(parents=True)
    standalone.write_text((old / "controls" / "catalog.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    diff = diff_catalogs(load_snapshot(standalone, label="loose"), load_snapshot(new, label="new"))
    assert diff.profiles_compared is False
    assert diff.added_profiles == ()
    assert diff.removed_profiles == ()
    # Controls are still compared on a bare catalog.
    assert [r.id for r in diff.added_controls] == ["D"]
    assert "not compared" in render_human(diff)


def test_to_dict_is_json_serializable(tmp_path: Path) -> None:
    old, new = _old_and_new(tmp_path)
    diff = diff_catalogs(load_snapshot(old, label="old"), load_snapshot(new, label="new"))
    payload = json.loads(json.dumps(diff.to_dict()))
    assert payload["controls"]["added"] == [{"id": "D", "title": "Control D"}]
    assert payload["profiles"]["removed"] == ["p2"]
    assert payload["from"] == "old"
    assert payload["to"] == "new"


def test_missing_path_raises_invalid_input(tmp_path: Path) -> None:
    with pytest.raises(InvalidInputError):
        load_snapshot(tmp_path / "does-not-exist", label="from")


def test_dir_without_catalog_raises_invalid_input(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(InvalidInputError):
        load_snapshot(empty, label="from")
