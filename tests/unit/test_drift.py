"""Tests for :mod:`oss_policy_kit.application.drift`.

Rewritten 2026-08-05. Every test here previously built the ``reports/1.0`` shape —
``results[]`` with ``control_id``/``status`` in lowercase — which v9.0.0 removed under
ADR-043. The suite stayed green while ``diff-reports`` was blind to every report the kit
actually writes, because the tests asserted against the same wrong contract the code read.

The end-to-end consequence and the contract-rejection rules live in
``test_drift_reports_2_0.py``; this file covers the mechanics.
"""

from __future__ import annotations

from oss_policy_kit.application.drift import compute_drift
from oss_policy_kit.application.reporting import render_drift_report


def _row(cid: str, title: str, state: str) -> dict:
    """One ``controls[]`` entry in the shape ``reports/2.0`` emits."""

    return {
        "id": cid,
        "title": title,
        "category": "x",
        "state": state,
        "lifecycle": "stable",
        "profile": "p",
        "assurance": "deterministic",
        "confidence": "high",
        "weight": 1,
        "message": "r",
        "remediation": "m",
        "evidence": {"source_type": "static_clone"},
        "owner": None,
        "expires_at": None,
        "extra": {},
        "waiver": None,
        "finding_id": f"{cid}@p",
    }


def _report(controls: list[dict], **extra: object) -> dict:
    base: dict = {"contract_version": "reports/2.0", "controls": controls}
    base.update(extra)
    return base


def test_no_changes_empty_drift() -> None:
    rows = [_row("A", "t", "PASS"), _row("B", "u", "FAIL")]
    d = compute_drift(_report(rows, kit_version="1"), _report(list(rows), kit_version="2"))
    assert not d.regressions
    assert not d.improvements
    assert not d.has_regressions


def test_regression_pass_to_fail() -> None:
    d = compute_drift(
        _report([_row("X", "xt", "PASS")], kit_version="1"),
        _report([_row("X", "xt", "FAIL")], kit_version="2"),
    )
    assert len(d.regressions) == 1
    assert d.regressions[0].control_id == "X"
    assert d.has_regressions


def test_improvement_fail_to_pass() -> None:
    d = compute_drift(
        _report([_row("Y", "yt", "FAIL")], kit_version="1"),
        _report([_row("Y", "yt", "PASS")], kit_version="2"),
    )
    assert len(d.improvements) == 1
    assert not d.has_regressions


def test_improvement_fail_to_self_attested() -> None:
    d = compute_drift(
        _report([_row("Y2", "y2", "FAIL")], kit_version="1"),
        _report([_row("Y2", "y2", "SELF_ATTESTED")], kit_version="2"),
    )
    assert len(d.improvements) == 1
    assert not d.has_regressions


def test_self_attested_to_fail_is_regression() -> None:
    d = compute_drift(
        _report([_row("Z", "zt", "SELF_ATTESTED")], kit_version="1"),
        _report([_row("Z", "zt", "FAIL")], kit_version="2"),
    )
    assert d.has_regressions


def test_new_control_in_after() -> None:
    d = compute_drift(
        _report([_row("A", "a", "PASS")], kit_version="1"),
        _report([_row("A", "a", "PASS"), _row("B", "b", "PASS")], kit_version="2"),
    )
    assert d.new_controls == ["B"]


def test_removed_control() -> None:
    d = compute_drift(
        _report([_row("A", "a", "PASS"), _row("B", "b", "PASS")], kit_version="1"),
        _report([_row("A", "a", "PASS")], kit_version="2"),
    )
    assert d.removed_controls == ["B"]


def test_expired_waiver() -> None:
    w_before = _row("W", "w", "PASS")
    w_before["waiver"] = {"control_id": "W", "justification": "x", "owner": "o", "status": "active"}
    d = compute_drift(
        _report([w_before], kit_version="1"),
        _report([_row("W", "w", "PASS")], kit_version="2"),
    )
    assert "W" in d.expired_waivers


def test_render_drift_json_roundtrip_keys() -> None:
    d = compute_drift(
        _report([_row("X", "xt", "PASS")], kit_version="1", profile={"id": "p1"}),
        _report([_row("X", "xt", "FAIL")], kit_version="2", profile={"id": "p1"}),
    )
    out = render_drift_report(d, "json")
    assert "has_regressions" in out
    assert "regressions" in out
    assert "profile_mismatch" in out
    assert "before_profile_id" in out
    assert "after_profile_id" in out


def test_render_drift_table_without_color_has_no_ansi_sequences() -> None:
    d = compute_drift(
        _report([_row("X", "xt", "PASS")], kit_version="1", profile={"id": "p1"}),
        _report([_row("X", "xt", "FAIL")], kit_version="2", profile={"id": "p1"}),
    )
    out = render_drift_report(d, "table", color=False)
    assert "\x1b[" not in out


# --- profile id extraction -------------------------------------------------------------
#
# ``reports/2.0`` nests the profile under ``profile.id``. The flat ``profile_id`` fallback
# is kept only so a hand-assembled or partial payload does not silently produce a false
# "no mismatch"; it is not a supported input contract.


def test_profile_id_read_from_nested_object() -> None:
    d = compute_drift(
        _report([_row("X", "xt", "PASS")], kit_version="5", profile={"id": "github-level-1"}),
        _report([_row("X", "xt", "PASS")], kit_version="5", profile={"id": "github-level-1"}),
    )
    assert d.before_profile_id == "github-level-1"
    assert d.profile_mismatch is False


def test_profile_id_falls_back_to_flat_key_on_partial_payload() -> None:
    d = compute_drift(
        _report([_row("X", "xt", "PASS")], profile_id="github-level-1"),
        _report([_row("X", "xt", "PASS")], profile_id="github-level-1"),
    )
    assert d.before_profile_id == "github-level-1"
    assert d.profile_mismatch is False


def test_profile_mismatch_detected_from_nested_shape() -> None:
    d = compute_drift(
        _report([_row("X", "xt", "PASS")], profile={"id": "github-level-1"}),
        _report([_row("X", "xt", "PASS")], profile={"id": "github-level-2"}),
    )
    assert d.before_profile_id == "github-level-1"
    assert d.after_profile_id == "github-level-2"
    assert d.profile_mismatch is True


def test_nested_profile_wins_over_flat_key_when_both_present() -> None:
    """A hybrid payload must resolve to the nested id, never the stale flat one."""

    d = compute_drift(
        _report([_row("X", "xt", "PASS")], profile={"id": "github-level-3"}, profile_id="github-level-1"),
        _report([_row("X", "xt", "PASS")], profile={"id": "github-level-3"}, profile_id="github-level-1"),
    )
    assert d.before_profile_id == "github-level-3"
    assert d.profile_mismatch is False


def test_report_without_any_profile_key_yields_none_and_no_false_mismatch() -> None:
    d = compute_drift(
        _report([_row("X", "xt", "PASS")], kit_version="1"),
        _report([_row("X", "xt", "PASS")], kit_version="2"),
    )
    assert d.before_profile_id is None
    assert d.after_profile_id is None
    assert d.profile_mismatch is False


def test_profile_mismatch_with_empty_control_sets() -> None:
    d = compute_drift(
        _report([], profile={"id": "github-level-1"}, kit_version="1"),
        _report([], profile={"id": "github-level-2"}, kit_version="2"),
    )
    assert d.profile_mismatch is True
