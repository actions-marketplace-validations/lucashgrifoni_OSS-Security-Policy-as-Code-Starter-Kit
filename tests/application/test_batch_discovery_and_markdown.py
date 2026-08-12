"""Which directories a batch run picks up, and what its Markdown says about where things went.

A batch run evaluates every repository under one root, so discovery decides what gets audited at
all. A directory silently skipped is a repository nobody looked at, and the summary at the end
counts only what it visited -- so it reads as a complete sweep either way.

The Markdown is the shareable half of that run. It carries paths, which is why the fallback
matters: a report written outside the batch output directory cannot be shown relative to it, and
the absolute path it would fall back to carries the auditor's home directory and OS account name
(M-002). It is reduced to a basename unless the operator explicitly asked otherwise.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from oss_policy_kit.application.batch_evaluate import (
    BatchRunRow,
    _batch_md_artifact_lines,
    _BatchStats,
    _render_batch_markdown,
    discover_batch_targets,
)
from oss_policy_kit.domain.errors import InvalidInputError


def _row(output_dir: Path, name: str = "repo-a") -> BatchRunRow:
    return BatchRunRow(
        target_name=name,
        target_path=f"./{name}",
        profile_id="github-level-2",
        summary_by_status={"pass": 10, "fail": 1},
        report_path_json=str(output_dir / name / "evaluation-report.json"),
        report_path_md=str(output_dir / name / "evaluation-report.md"),
    )


def _stats(*, comparison_lines: list[str] | None = None, gap_hits: Counter[str] | None = None) -> _BatchStats:
    return _BatchStats(
        totals={"pass": 10, "fail": 1},
        dist={"0": 1, "1-5": 0, "6-10": 0, "11+": 0},
        comparison_lines=comparison_lines or [],
        gap_hits=gap_hits or Counter(),
        all_tied=False,
        common_fail_count=0,
    )


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def test_child_directories_are_the_targets(tmp_path: Path) -> None:
    (tmp_path / "repo-a").mkdir()
    (tmp_path / "repo-b").mkdir()

    assert [p.name for p in discover_batch_targets(tmp_path, include=None, exclude=None)] == ["repo-a", "repo-b"]


def test_a_file_beside_the_repositories_is_not_a_target(tmp_path: Path) -> None:
    """A `README.md` in the batch root is not a repository, and evaluating it would fail oddly."""

    (tmp_path / "repo-a").mkdir()
    (tmp_path / "README.md").write_text("notes\n", encoding="utf-8")

    assert [p.name for p in discover_batch_targets(tmp_path, include=None, exclude=None)] == ["repo-a"]


def test_dot_directories_are_left_alone(tmp_path: Path) -> None:
    """`.git` and friends are not repositories to audit; they are inside them."""

    (tmp_path / "repo-a").mkdir()
    (tmp_path / ".cache").mkdir()

    assert [p.name for p in discover_batch_targets(tmp_path, include=None, exclude=None)] == ["repo-a"]


def test_include_and_exclude_narrow_the_sweep(tmp_path: Path) -> None:
    for name in ("svc-api", "svc-web", "tool-cli"):
        (tmp_path / name).mkdir()

    assert [p.name for p in discover_batch_targets(tmp_path, include="svc-*", exclude=None)] == ["svc-api", "svc-web"]
    assert [p.name for p in discover_batch_targets(tmp_path, include=None, exclude="svc-*")] == ["tool-cli"]


def test_a_root_that_cannot_be_listed_is_a_usage_error_naming_no_path(tmp_path: Path) -> None:
    """Exit 2 with the OS reason only: the resolved root would carry the account name (M-002)."""

    missing = tmp_path / "not-there"
    with pytest.raises(InvalidInputError) as excinfo:
        discover_batch_targets(missing, include=None, exclude=None)

    assert "not-there" in str(excinfo.value)
    assert str(tmp_path) not in str(excinfo.value)


# --------------------------------------------------------------------------- #
# Where the reports went
# --------------------------------------------------------------------------- #


def test_reports_inside_the_output_directory_are_named_relative_to_it(tmp_path: Path) -> None:
    lines = _batch_md_artifact_lines([_row(tmp_path)], tmp_path)

    assert any("repo-a/evaluation-report.json" in ln for ln in lines)
    assert not any(str(tmp_path) in ln for ln in lines)


def test_a_report_written_elsewhere_is_reduced_to_its_filename(tmp_path: Path) -> None:
    """The Markdown is shareable; an absolute path here leaks the auditor's home directory."""

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    lines = _batch_md_artifact_lines([_row(elsewhere)], tmp_path / "out")

    assert any("`evaluation-report.json`" in ln for ln in lines)
    assert not any(str(tmp_path) in ln for ln in lines)


def test_the_operator_can_ask_for_the_full_path_back(tmp_path: Path) -> None:
    """Opt-in, because a local run wants the path it can click on."""

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    lines = _batch_md_artifact_lines([_row(elsewhere)], tmp_path / "out", include_absolute_path=True)

    assert any(str(elsewhere.resolve()) in ln for ln in lines)


# --------------------------------------------------------------------------- #
# The summary document
# --------------------------------------------------------------------------- #


def _render(tmp_path: Path, stats: _BatchStats) -> str:
    return _render_batch_markdown(
        [_row(tmp_path)],
        generated_at="2026-08-12T00:00:00Z",
        target_root=tmp_path,
        profile_ids=["github-level-2"],
        eval_queue_len=1,
        gate_violated=False,
        policy="fail",
        stats=stats,
        skipped_dirs=[],
        output_dir=tmp_path,
    )


def test_a_single_profile_run_prints_no_comparison_section(tmp_path: Path) -> None:
    """There is nothing to compare against, and an empty heading is worse than no heading."""

    assert "Quick comparison" not in _render(tmp_path, _stats())


def test_a_multi_profile_run_prints_the_comparison(tmp_path: Path) -> None:
    md = _render(tmp_path, _stats(comparison_lines=["All **tied** at 1 fail"]))

    assert "Quick comparison" in md
    assert "tied" in md


def test_no_repeated_failures_prints_no_repeated_failures_table(tmp_path: Path) -> None:
    assert "Repeated failing controls" not in _render(tmp_path, _stats())


def test_repeated_failures_are_tabulated_with_their_counts(tmp_path: Path) -> None:
    """This table is the reason to run a batch at all: what fails everywhere, not once."""

    md = _render(tmp_path, _stats(gap_hits=Counter({"CI-PIN-008": 3, "GH-PROV-023": 2})))

    assert "Repeated failing controls" in md
    assert "| `CI-PIN-008` | 3 |" in md
