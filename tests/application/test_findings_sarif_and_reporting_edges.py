"""Projecting findings into SARIF, and the reporting helpers that decide what a report admits.

The SARIF projection is what GitHub code scanning turns into alerts, so what it attaches to a
result decides what a reviewer can act on. A finding with a file gets a location; one with a
line gets a region; one with an end line gets a range. Each of those is optional in the source
artifact, and emitting a half-built location -- a region with no file, a range with no start --
produces a SARIF document consumers reject or silently mis-place.

The reporting helpers are about a report never claiming more than it knows: an atomic write
that removes its temp file even when interrupted, a live-collection block that is absent rather
than empty when nothing was collected, and a `degraded` marker that only appears when the run
actually degraded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import reporting
from oss_policy_kit.application.findings_sarif_export import _result_for, render_findings_sarif


def _finding(
    *,
    fid: str = "opk-fk/v1:abc",
    rule: str = "RULE-1",
    file: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    vuln_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": fid,
        "rule": rule,
        "message": "something to fix",
        "severity": {"normalized": "high"},
        "priority": {"rank": 1},
        "correlation": {"merged_from": 1},
        "waiver": {"waived": False},
        "vulnerability_ids": vuln_ids or [],
        "sources": [{"tool": "semgrep", "source_path": "sast.sarif"}],
        "location": {"file": file, "line_start": line_start, "line_end": line_end},
    }


# --------------------------------------------------------------------------- #
# SARIF locations are built only as far as the data goes
# --------------------------------------------------------------------------- #


def test_a_finding_with_no_file_carries_no_location() -> None:
    """A location with no artifact is not a location; consumers reject or misplace it."""

    assert "locations" not in _result_for(_finding())


def test_a_finding_with_a_file_but_no_line_carries_no_region() -> None:
    result = _result_for(_finding(file="src/app.py"))
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/app.py"
    assert "region" not in physical


def test_a_finding_with_a_start_line_carries_a_single_line_region() -> None:
    result = _result_for(_finding(file="src/app.py", line_start=12))
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 12}


def test_a_finding_with_both_lines_carries_a_range() -> None:
    result = _result_for(_finding(file="src/app.py", line_start=12, line_end=18))
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 12, "endLine": 18}


def test_vulnerability_ids_are_attached_only_when_present() -> None:
    with_ids = _result_for(_finding(vuln_ids=["CVE-2026-1"]))
    without = _result_for(_finding())
    assert with_ids["properties"]["vulnerability_ids"] == ["CVE-2026-1"]
    assert "vulnerability_ids" not in without["properties"]


def test_the_same_rule_seen_twice_is_declared_once() -> None:
    """A rule advertises what was checked; two findings of one rule are still one rule."""

    doc = render_findings_sarif({"findings": [_finding(), _finding(fid="opk-fk/v1:def")]})
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["RULE-1"]
    assert len(doc["runs"][0]["results"]) == 2


def test_a_finding_without_a_rule_falls_back_to_its_id() -> None:
    doc = render_findings_sarif({"findings": [_finding(rule="")]})
    assert [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]] == ["opk-fk/v1:abc"]


# --------------------------------------------------------------------------- #
# Reporting helpers
# --------------------------------------------------------------------------- #


def test_an_interrupted_write_leaves_no_temp_file_behind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`BaseException` on purpose: a Ctrl-C must not leave a half-written report beside the real one."""

    tmp = tmp_path / "report.json.tmp"
    tmp.write_text("partial", encoding="utf-8")
    target = tmp_path / "report.json"

    def _boom(*_a: object, **_k: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(reporting.os, "replace", _boom)
    with pytest.raises(KeyboardInterrupt):
        reporting._publish_staged(tmp, target, "final")

    assert not tmp.exists(), "the staged file survived the interrupt"


def test_no_live_collection_metadata_yields_no_block() -> None:
    """Absent, not empty: an empty object would read as 'we collected nothing', which differs."""

    assert reporting._live_collection_dict(None) is None


@pytest.mark.parametrize(
    ("control_id", "fragment"),
    [
        ("PLAT-BRPROT-015", "Platform settings"),
        ("GOV-SEC-001", ""),
    ],
)
def test_a_control_id_maps_to_its_structural_bucket(control_id: str, fragment: str) -> None:
    bucket = reporting._structural_bucket(control_id)
    assert isinstance(bucket, str) and bucket
    if fragment:
        assert fragment in bucket


def test_no_matching_evidence_source_yields_nothing() -> None:
    """Nothing to attribute the reference to, so it stays unattributed rather than guessed."""

    assert reporting._take_matching_source([], {"file": "x"}) is None
    assert reporting._take_matching_source(["a.json", "b.json"], {}) is None


def test_a_scorecard_explanation_that_is_not_text_is_left_alone() -> None:
    """Only a string can carry an embedded host path; anything else is passed through."""

    supplemental = {"path": "/home/auditor/scorecard.json", "explanation": {"unexpected": True}}
    out = reporting._sanitize_scorecard_supplemental(supplemental, include_absolute=False)
    assert out is not None
    assert out["explanation"] == {"unexpected": True}
    assert "auditor" not in out["path"]


def test_a_scorecard_explanation_that_is_text_is_scrubbed() -> None:
    """The counterpart: with a real string, the embedded path is sanitised."""

    supplemental = {"explanation": f"read from {Path('/home/auditor/scorecard.json')}"}
    out = reporting._sanitize_scorecard_supplemental(supplemental, include_absolute=False)
    assert out is not None
    assert "auditor" not in out["explanation"]


def test_live_collection_metadata_is_rendered_when_a_collection_happened() -> None:
    """Present means the run really called a platform API; the block records which."""

    meta = reporting.LiveCollectionMetadata(
        performed=True,
        platform="github",
        collected_at="2026-08-11T00:00:00Z",
        api_evidence_sources=["github-rulesets.json"],
    )
    block = reporting._live_collection_dict(meta)
    assert block is not None
    assert block["platform"] == "github"
    assert block["performed"] is True
