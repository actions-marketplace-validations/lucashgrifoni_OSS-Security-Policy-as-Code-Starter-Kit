"""Branch coverage for the Scorecard adapter coercion + auto-load helpers."""

from __future__ import annotations

import math
from pathlib import Path

import yaml

from oss_policy_kit.adapters.scorecard_json import (
    ScorecardBundle,
    ScorecardCheck,
    _coerce_aggregate_score,
    _coerce_checks,
    checks_as_map,
    load_scorecard_auto,
)

# --------------------------------------------------------------------------- #
# _coerce_checks
# --------------------------------------------------------------------------- #


def test_coerce_checks_none_and_non_list() -> None:
    assert _coerce_checks(None) == []
    assert _coerce_checks("not-a-list") == []
    assert _coerce_checks(123) == []


def test_coerce_checks_unwraps_dict_with_checks() -> None:
    out = _coerce_checks({"checks": [{"name": "CodeQL", "score": 9}]})
    assert [c.name for c in out] == ["CodeQL"]
    assert out[0].score == 9


def test_coerce_checks_skips_non_dict_and_blank_names_and_reads_details() -> None:
    out = _coerce_checks(
        [
            123,  # not a dict -> skipped
            {"name": "   "},  # blank name -> skipped
            {"name": "Has-Reason", "reason": "because"},
            {"name": "Has-Details", "details": "see-here"},
        ]
    )
    by_name = {c.name: c for c in out}
    assert set(by_name) == {"Has-Reason", "Has-Details"}
    assert by_name["Has-Reason"].reason == "because"
    assert by_name["Has-Details"].reason == "see-here"


# --------------------------------------------------------------------------- #
# _coerce_aggregate_score
# --------------------------------------------------------------------------- #


def test_coerce_aggregate_score_branches() -> None:
    assert _coerce_aggregate_score(True) is None  # bool rejected first
    assert _coerce_aggregate_score(None) is None
    assert _coerce_aggregate_score("7.5") is None  # non-numeric -> else None
    assert _coerce_aggregate_score(math.nan) is None  # NaN guard
    assert _coerce_aggregate_score(-0.1) is None  # below range
    assert _coerce_aggregate_score(10.1) is None  # above range
    assert _coerce_aggregate_score(0) == 0.0
    assert _coerce_aggregate_score(7.5) == 7.5


# --------------------------------------------------------------------------- #
# load_scorecard_auto — YAML branch + JSON fallback
# --------------------------------------------------------------------------- #


def test_load_scorecard_auto_yaml_top_level_score(tmp_path: Path) -> None:
    p = tmp_path / "sc.yaml"
    p.write_text(yaml.safe_dump({"checks": [{"name": "Pinned-Dependencies", "score": 8}], "score": 7.5}), "utf-8")
    bundle = load_scorecard_auto(p)
    assert [c.name for c in bundle.checks] == ["Pinned-Dependencies"]
    assert bundle.aggregate_score == 7.5


def test_load_scorecard_auto_yaml_nested_scorecard_score(tmp_path: Path) -> None:
    p = tmp_path / "sc.yml"
    p.write_text(
        yaml.safe_dump({"checks": [{"name": "Token-Permissions", "score": 10}], "scorecard": {"score": 6.0}}), "utf-8"
    )
    bundle = load_scorecard_auto(p)
    assert bundle.aggregate_score == 6.0


def test_load_scorecard_auto_yaml_non_dict(tmp_path: Path) -> None:
    p = tmp_path / "sc.yaml"
    p.write_text(yaml.safe_dump([1, 2, 3]), "utf-8")
    bundle = load_scorecard_auto(p)
    assert bundle.checks == []
    assert bundle.aggregate_score is None


def test_load_scorecard_auto_json_fallback(tmp_path: Path) -> None:
    p = tmp_path / "sc.json"
    p.write_text('{"checks": [{"name": "Fuzzing", "score": 5}], "score": 4.2}', "utf-8")
    bundle = load_scorecard_auto(p)
    assert [c.name for c in bundle.checks] == ["Fuzzing"]
    assert bundle.aggregate_score == 4.2


# --------------------------------------------------------------------------- #
# checks_as_map
# --------------------------------------------------------------------------- #


def test_checks_as_map_none_and_populated() -> None:
    assert checks_as_map(None) == {}
    bundle = ScorecardBundle(checks=[ScorecardCheck(name="CodeQL", score=10)])
    m = checks_as_map(bundle)
    assert m["codeql"].score == 10
