"""The human view of a correlated findings run, and where its inputs are refused.

The table is capped, so the one thing it must never do is imply it showed everything. When
more findings exist than fit, the trailing line says how many were left out and where the full
artifact is -- without it a reader takes the top ten for the whole set.

The tags carry the facts that change a finding's priority: waived, on CISA KEV, its EPSS
probability, and how many source findings were merged into it. Each is optional and each is
asserted present and absent, because a tag that never renders is indistinguishable from a
finding that does not have that property.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.cli import correlate_findings as cf
from oss_policy_kit.domain.errors import InvalidInputError


def _finding(
    *,
    rank: int = 1,
    waived: bool = False,
    kev: bool = False,
    epss: float | None = None,
    merged_from: int = 1,
) -> dict[str, Any]:
    return {
        "id": "opk-fk/v1:abc",
        "rule": "RULE-1",
        "severity": {"normalized": "high"},
        "priority": {"rank": rank},
        "correlation": {"merged_from": merged_from},
        "waiver": {"waived": waived},
        "kev": kev,
        "epss": epss,
        "location": {"file": "src/app.py", "line_start": 3, "line_end": None},
    }


def _report(findings: list[dict[str, Any]], *, total: int | None = None) -> dict[str, Any]:
    from oss_policy_kit.application.finding_normalization import NORMALIZED_SEVERITIES

    return {
        "findings": findings,
        "findings_total": total if total is not None else len(findings),
        "findings_by_severity": dict.fromkeys(NORMALIZED_SEVERITIES, 0) | {"high": len(findings)},
        "sources_read": [{"tool": "semgrep", "status": "ok", "source_path": "sast.sarif"}],
        "correlation": {"merged_groups": 0, "cross_tool_merges": 0},
    }


# --------------------------------------------------------------------------- #
# Tags
# --------------------------------------------------------------------------- #


def test_a_plain_finding_carries_no_tags() -> None:
    assert cf._finding_tags(_finding()) == ""


@pytest.mark.parametrize(
    ("kwargs", "fragment"),
    [
        ({"waived": True}, "WAIVED"),
        ({"kev": True}, "KEV"),
        ({"epss": 0.4237}, "EPSS=0.42"),
        ({"merged_from": 3}, "merged x3"),
    ],
)
def test_each_priority_fact_shows_up_as_its_own_tag(kwargs: dict[str, Any], fragment: str) -> None:
    """These are the facts that move a finding up the list; each must be visible."""

    assert fragment in cf._finding_tags(_finding(**kwargs))


def test_an_epss_of_zero_is_still_shown() -> None:
    """0.00 is a measured probability, not a missing one; `is not None` is the right test."""

    assert "EPSS=0.00" in cf._finding_tags(_finding(epss=0.0))


def test_a_finding_merged_from_one_source_is_not_labelled_merged() -> None:
    """Every finding has one source; saying "merged x1" would be noise on every row."""

    assert "merged" not in cf._finding_tags(_finding(merged_from=1))


def test_all_tags_render_together() -> None:
    tags = cf._finding_tags(_finding(waived=True, kev=True, epss=0.5, merged_from=2))
    assert tags.count(",") == 3, tags


# --------------------------------------------------------------------------- #
# The capped table
# --------------------------------------------------------------------------- #


def test_a_truncated_table_says_how_many_were_left_out(capsys: pytest.CaptureFixture[str]) -> None:
    """Without this line the top rows read as the whole set."""

    shown = [_finding(rank=i) for i in range(cf._HUMAN_TABLE_CAP)]
    cf._render_human(_report(shown, total=cf._HUMAN_TABLE_CAP + 7), "findings.json")
    out = capsys.readouterr().out
    assert "and 7 more" in out
    assert "findings.json" in out


def test_a_complete_table_says_nothing_about_more(capsys: pytest.CaptureFixture[str]) -> None:
    cf._render_human(_report([_finding()]), "findings.json")
    assert "more (see" not in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Writing the artifact
# --------------------------------------------------------------------------- #


def test_a_nested_output_path_has_its_directory_created(tmp_path: Path) -> None:
    out = tmp_path / "reports" / "nested" / "findings.json"
    cf._write_artifact(_report([_finding()]), out)
    assert json.loads(out.read_text(encoding="utf-8"))["findings_total"] == 1


def test_a_bare_filename_is_written_in_place(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`Path("x.json").parent` is `.`, which already exists; mkdir must be skipped."""

    monkeypatch.chdir(tmp_path)
    cf._write_artifact(_report([_finding()]), Path("findings.json"))
    assert (tmp_path / "findings.json").is_file()


# --------------------------------------------------------------------------- #
# Input refusals
# --------------------------------------------------------------------------- #


def test_a_waivers_path_that_is_not_a_file_is_refused(tmp_path: Path) -> None:
    """A directory passed to --waivers would otherwise fail later and less clearly."""

    (tmp_path / "waivers.yaml").mkdir()
    with pytest.raises(InvalidInputError, match="is not a file"):
        cf._resolve_paths(
            target=str(tmp_path), output=Path("findings.json"), waivers=Path("waivers.yaml"), enrichment_file=None
        )


def test_a_missing_waivers_path_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InvalidInputError, match="is not a file"):
        cf._resolve_paths(
            target=str(tmp_path), output=Path("findings.json"), waivers=Path("nope.yaml"), enrichment_file=None
        )


def test_no_waivers_flag_is_not_a_refusal(tmp_path: Path) -> None:
    """The counterpart: the check must only fire when the flag was actually passed."""

    resolved = cf._resolve_paths(target=str(tmp_path), output=Path("findings.json"), waivers=None, enrichment_file=None)
    assert resolved is not None


def test_an_unexpected_error_reaches_the_operator_as_a_message(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bug in correlation still has to leave a usable CI log, not a stack trace."""

    from typer.testing import CliRunner

    from oss_policy_kit.cli.main import app

    def _boom(*_a: object, **_k: object) -> object:
        raise RuntimeError("nobody anticipated this")

    monkeypatch.setattr(cf, "_run_correlate_findings", _boom)
    res = CliRunner().invoke(app, ["correlate-findings", "--target", str(tmp_path)])

    assert res.exit_code != 0
    assert "Traceback" not in res.output, res.output
