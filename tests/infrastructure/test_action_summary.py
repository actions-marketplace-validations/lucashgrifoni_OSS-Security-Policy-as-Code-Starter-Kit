"""Tests for scripts/action_summary.py (the composite Action's job summary + annotations)."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parents[2] / "scripts" / "action_summary.py"
_spec = importlib.util.spec_from_file_location("action_summary", _SCRIPT)
assert _spec is not None and _spec.loader is not None
action_summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(action_summary)


def test_summary_has_counts_table_and_failing_section() -> None:
    report = {
        # reports/2.0 embeds the full profile object; the summary must extract its id.
        "profile": {"id": "github-level-1", "title": "GitHub OSS starter baseline (level 1)"},
        "controls": [
            {"id": "A", "state": "PASS"},
            {"id": "B", "state": "FAIL", "message": "missing thing"},
            {"id": "C", "state": "UNKNOWN"},
        ],
    }
    summary = action_summary.build_summary(report)
    assert "`github-level-1`" in summary  # id extracted, not the whole dict
    assert "title" not in summary  # the profile dict is not dumped verbatim
    assert "| PASS | 1 |" in summary
    assert "| FAIL | 1 |" in summary
    assert "### Failing controls" in summary
    assert "`B`" in summary and "missing thing" in summary


def test_annotations_error_for_fail_warning_for_review() -> None:
    report = {
        "controls": [
            {"id": "B", "state": "FAIL", "reason": "bad"},
            {"id": "C", "state": "UNKNOWN", "reason": "review me"},
            {"id": "D", "state": "PASS"},
        ]
    }
    buf = io.StringIO()
    action_summary.emit_annotations(report, buf)
    out = buf.getvalue()
    assert "::error title=B::bad" in out
    assert "::warning title=C::review me" in out
    assert "title=D" not in out  # PASS controls get no annotation


def test_main_writes_to_github_step_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps({"profile": "p", "controls": [{"id": "A", "state": "PASS"}]}), encoding="utf-8")
    rc = action_summary.main(["action_summary.py", str(report_file)])
    assert rc == 0
    assert "## oss-policy-kit" in summary_file.read_text(encoding="utf-8")


def test_main_is_non_fatal_on_missing_report(tmp_path: Path) -> None:
    # A missing/unreadable report must not crash the Action (returns 0).
    assert action_summary.main(["action_summary.py", str(tmp_path / "nope.json")]) == 0
