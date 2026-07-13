"""Regression tests for the v10.0.2 path-leak / dedup hardening (group ``path-leak-loader``).

Each test fails against v10.0.1 and passes after the fix:

* #23 — ``resolve_existing_dir`` echoed the RESOLVED absolute path (cwd/home/OS username
  leak, M-002) for a relative non-existent ``--target``.
* #21 — ``load_catalog`` echoed the resolved absolute ``--kit-root`` path plus the raw
  OSError repr when ``controls/catalog.yaml`` was missing.
* #22 — ``load_profile`` echoed the resolved absolute path of an external ``--profile``
  YAML that failed to parse (and on the sibling missing-id / no-controls branches).
* #17 — an external profile listing the same control id more than once inflated
  ``controls_total`` / ``summary_by_status`` / the weighted score; ids are now de-duped
  (first-seen order preserved) while bundled profiles stay unaffected.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.conftest import EXAMPLE_HARDENED

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile,
    load_profile_by_id,
)
from oss_policy_kit.domain.errors import InvalidInputError, LoadError

# A distinctive path component that stands in for the OS username / home directory. It is
# long enough that if any error message interpolated the absolute path it would appear
# verbatim; asserting its ABSENCE is short-path-normalization proof (we never call
# ``resolve()`` on it in the test, so no Windows 8.3 alias can hide it).
_LEAK_MARKER = "USERNAME_LEAK_MARKER_7Q"


# --------------------------------------------------------------------------- #
# #23 — resolve_existing_dir echoes the user string, not the resolved path
# --------------------------------------------------------------------------- #


def test_resolve_existing_dir_relative_target_does_not_leak_absolute_path() -> None:
    rel = "nope-this-target-does-not-exist-xyz"
    with pytest.raises(InvalidInputError) as excinfo:
        resolve_existing_dir(rel)
    msg = excinfo.value.message
    # The echoed path must be EXACTLY the user-supplied string (mutation-proof: the buggy
    # version echoed ``Path(rel).resolve()`` which contains separators and != rel).
    echoed = msg.split("Not a directory or does not exist: ", 1)[1]
    assert echoed == rel
    # And the resolved absolute path (the previous leak) must be absent.
    assert str(Path(rel).resolve()) not in msg


# --------------------------------------------------------------------------- #
# #21 — load_catalog does not leak the resolved --kit-root absolute path
# --------------------------------------------------------------------------- #


def test_load_catalog_missing_file_does_not_leak_absolute_path(tmp_path: Path) -> None:
    # Simulate merge_kit_root's already-resolved absolute path with a distinctive marker
    # component, pointing at a catalog that does not exist.
    missing = tmp_path / _LEAK_MARKER / "controls" / "catalog.yaml"
    with pytest.raises(LoadError) as excinfo:
        load_catalog(missing)
    msg = excinfo.value.message
    assert "catalog.yaml" in msg  # basename kept for usefulness
    assert _LEAK_MARKER not in msg  # M-002: no absolute path / home / username
    assert str(missing) not in msg
    assert str(missing.parent) not in msg


# --------------------------------------------------------------------------- #
# #22 — load_profile does not leak the resolved external --profile path
# --------------------------------------------------------------------------- #


def _write(marker_dir: Path, name: str, text: str) -> Path:
    marker_dir.mkdir(parents=True, exist_ok=True)
    p = marker_dir / name
    p.write_text(text, encoding="utf-8")
    return p


def test_load_profile_parse_error_does_not_leak_absolute_path(tmp_path: Path) -> None:
    marker_dir = tmp_path / _LEAK_MARKER
    bad = _write(marker_dir, "custom-profile.yaml", "controls: [GOV-SEC-001\n")  # unterminated flow seq
    with pytest.raises(LoadError) as excinfo:
        load_profile(bad)
    msg = excinfo.value.message
    assert "Failed to load profile" in msg
    assert "custom-profile.yaml" in msg  # basename kept
    assert _LEAK_MARKER not in msg  # M-002
    assert str(marker_dir) not in msg


def test_load_profile_missing_id_and_no_controls_do_not_leak_absolute_path(tmp_path: Path) -> None:
    marker_dir = tmp_path / _LEAK_MARKER
    no_id = _write(marker_dir, "no-id.yaml", "title: X\ncontrols: [GOV-SEC-001]\n")
    with pytest.raises(LoadError) as excinfo:
        load_profile(no_id)
    assert _LEAK_MARKER not in excinfo.value.message

    no_controls = _write(marker_dir, "no-controls.yaml", "id: x\ntitle: X\n")
    with pytest.raises(LoadError) as excinfo:
        load_profile(no_controls)
    assert _LEAK_MARKER not in excinfo.value.message


# --------------------------------------------------------------------------- #
# #17 — duplicate control ids in an external profile are de-duplicated
# --------------------------------------------------------------------------- #


def test_external_profile_dedups_duplicate_control_ids(tmp_path: Path) -> None:
    src = (
        "id: dup\ntitle: Dup\ndescription: d\naudience: a\n"
        "controls: [GOV-SEC-001, CI-WF-005, GOV-SEC-001, GOV-SEC-001]\n"
    )
    p = tmp_path / "dup-profile.yaml"
    p.write_text(src, encoding="utf-8")
    spec = load_profile(p, validate_external_schema=True)
    # De-duplicated, first-seen order preserved.
    assert spec.control_ids == ("GOV-SEC-001", "CI-WF-005")


def test_duplicate_control_ids_do_not_inflate_report_counts(tmp_path: Path) -> None:
    root = bundled_kit_root()
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    src = "id: dup\ntitle: Dup\ndescription: d\naudience: a\ncontrols: [GOV-SEC-001, GOV-SEC-001, GOV-SEC-001]\n"
    p = tmp_path / "dup-profile.yaml"
    p.write_text(src, encoding="utf-8")
    profile = load_profile(p, validate_external_schema=True)
    report = evaluate_repository(
        repo_root=EXAMPLE_HARDENED,
        profile=profile,
        catalog=catalog,
        waiver_outcome=None,
        scorecard=None,
    )
    assert len(report.results) == 1
    assert sum(report.summary_by_status.values()) == 1
    # Weighted score reflects ONE control's weight, not three copies of it (pre-fix the
    # three duplicates inflated ``possible`` to 3x this control's weight).
    assert report.weighted_score.possible == catalog["GOV-SEC-001"].weight


def test_bundled_profiles_unaffected_by_dedup() -> None:
    # Sanity: bundled profiles carry no duplicates, so dedup is a no-op for them.
    profile = load_profile_by_id(bundled_kit_root(), "github-level-1")
    assert len(profile.control_ids) == len(set(profile.control_ids))
