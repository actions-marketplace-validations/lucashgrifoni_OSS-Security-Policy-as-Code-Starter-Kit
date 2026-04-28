"""Scorecard JSON adapter."""

import json
from pathlib import Path

from tests.conftest import ROOT

from oss_policy_kit.adapters.scorecard_json import load_scorecard_json


def test_load_scorecard_json_roundtrip(tmp_path: Path) -> None:
    payload = {
        "scorecard": {
            "version": "1",
            "checks": [{"name": "Code-QL", "score": 10}],
        }
    }
    p = tmp_path / "sc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_scorecard_json(p)
    assert bundle.checks
    assert bundle.checks[0].name == "Code-QL"


def test_fixture_scorecard_supplements_codeql(tmp_path: Path) -> None:
    p = ROOT / "tests" / "fixtures" / "scorecard.sample.json"
    bundle = load_scorecard_json(p)
    names = {c.name.lower() for c in bundle.checks}
    assert any("codeql" in n or "code-ql" in n for n in names)


def test_load_scorecard_json_captures_nested_aggregate_score(tmp_path: Path) -> None:
    """The official root ``score`` under ``scorecard`` must be captured."""
    payload = {
        "scorecard": {
            "version": "1",
            "score": 6.7,
            "checks": [{"name": "Pinned-Dependencies", "score": 8}],
        }
    }
    p = tmp_path / "sc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score == 6.7


def test_load_scorecard_json_captures_top_level_aggregate_score(tmp_path: Path) -> None:
    """A top-level ``score`` (unnested) must also be captured."""
    payload = {
        "score": 8.2,
        "checks": [{"name": "Token-Permissions", "score": 10}],
    }
    p = tmp_path / "sc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score == 8.2


def test_load_scorecard_json_rejects_out_of_range_aggregate(tmp_path: Path) -> None:
    """Aggregate scores outside the 0-10 range must be dropped, not clamped."""
    payload = {
        "scorecard": {
            "score": 42,
            "checks": [{"name": "Token-Permissions", "score": 10}],
        }
    }
    p = tmp_path / "sc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score is None
    assert bundle.checks


def test_load_scorecard_json_ignores_non_numeric_aggregate(tmp_path: Path) -> None:
    """Non-numeric ``score`` values (booleans, strings) must not leak through."""
    payload = {
        "scorecard": {
            "score": True,
            "checks": [{"name": "Token-Permissions", "score": 10}],
        }
    }
    p = tmp_path / "sc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_scorecard_json(p)
    assert bundle.aggregate_score is None


def test_load_scorecard_json_ignores_true_per_check_score(tmp_path: Path) -> None:
    payload = {
        "scorecard": {
            "version": "1",
            "checks": [{"name": "Pinned-Dependencies", "score": True}],
        }
    }
    p = tmp_path / "sc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_scorecard_json(p)
    assert bundle.checks
    assert bundle.checks[0].name == "Pinned-Dependencies"
    assert bundle.checks[0].score is None


def test_load_scorecard_json_ignores_false_per_check_score(tmp_path: Path) -> None:
    payload = {
        "scorecard": {
            "version": "1",
            "checks": [{"name": "Pinned-Dependencies", "score": False}],
        }
    }
    p = tmp_path / "sc.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    bundle = load_scorecard_json(p)
    assert bundle.checks
    assert bundle.checks[0].name == "Pinned-Dependencies"
    assert bundle.checks[0].score is None
