"""v10.0.7: how the report writers publish -- SARIF atomicity, pair consistency, drift markup.

Three defects from the clean-room validation of the built wheel, all in the
reporting layer's *publish* step rather than in what it renders:

- **The SARIF was written non-atomically.** ``write_sarif_report`` truncated the
  destination and wrote into it, while the JSON and Markdown writers had long since
  moved to a temp file and a rename. Measured in a 50-writer x 6-round storm with four
  reader threads: the reader parsed ``evaluation-report.sarif`` 43682 times and got
  invalid JSON 290 times, every sampled failure ``len == 0`` -- the truncate window. A
  CI step uploading that file to code scanning uploads a zero-byte SARIF, and an empty
  SARIF is indistinguishable from a clean repository.

- **A failed Markdown write left a NEW json beside a STALE md.** Seed an output
  directory from one target, hold only ``evaluation-report.md`` open, evaluate a
  different target: the JSON was replaced and the Markdown was not, so one directory
  held two files describing two different repositories, with nothing in either saying
  so. ``write_reports`` now publishes them as a pair.

- **The Rich drift table ate bracketed fragments of control ids.** Rich reads
  ``[word]`` as a style tag, so a control id ``[bold]GOV-SEC-001`` reached the operator
  as ``GOV-SEC-001`` -- a different control. ``--format markdown`` and ``--format json``
  always kept it whole, so only the table lied.

On test shape: the atomicity assertions here are deterministic (a spy on ``os.replace``
and a write that fails mid-flight) rather than thread storms. The truncate window is
reproduced exactly by a write that dies after the destination is opened, which is the
same ``len == 0`` the storm sampled -- and unlike a storm it fails every time the fix is
removed. ``test_uat_reporting_leaks_and_atomic_writes.py`` already carries the real
multi-writer storm for the JSON path.

Markers are separator-free directory-style names, never ``str(tmp_path)``: on Windows a
path assertion against serialized JSON is vacuous because ``json.dumps`` doubles the
backslashes.
"""

from __future__ import annotations

import errno
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import reporting as rp
from oss_policy_kit.application import sarif_writer as sw
from oss_policy_kit.application.drift import ControlDelta, DriftReport
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

# Distinctive, separator-free markers. Each names one *run*, so a mixed pair is visible
# as "the JSON says one and the Markdown says the other".
_TARGET_A = "alpha-marker-repo"
_TARGET_B = "bravo-marker-repo"


def _result(**over: Any) -> ControlResult:
    kwargs: dict[str, Any] = {
        "control_id": "GOV-SEC-001",
        "title": "Security policy present",
        "category": "governance",
        "status": ControlStatus.FAIL,
        "profile": "github-level-1",
        "evidence_sources": [],
        "confidence": "high",
        "reason": "no SECURITY.md",
        "remediation": "add SECURITY.md",
    }
    kwargs.update(over)
    return ControlResult(**kwargs)


def _report(*, target_path: str = _TARGET_A, results: list[ControlResult] | None = None) -> ExecutionReport:
    rows = results if results is not None else [_result()]
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-08-07T00:00:00Z",
        kit_version="10.0.7",
        target_path=target_path,
        profile_id="github-level-1",
        profile_title="GitHub level 1",
        summary_by_status={"fail": len(rows)},
        results=rows,
        operational_warnings=[],
    )


def _unencodable_report(*, target_path: str = _TARGET_A) -> ExecutionReport:
    """A report whose text cannot be UTF-8 encoded, to interrupt a write mid-flight.

    A lone surrogate reaches ``reason`` whenever an evaluator echoes text decoded from a
    malformed source file. The encoder raises *after* the destination has been opened,
    which is precisely the state a reader sampled as ``len == 0``.
    """

    return _report(target_path=target_path, results=[_result(reason="bad \ud800 text")])


def _replace_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the destination's content at the instant before each swap."""

    observed: list[str] = []
    real_replace = os.replace

    def spy(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        dest = Path(dst)
        observed.append(dest.read_text(encoding="utf-8") if dest.exists() else "<absent>")
        real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(rp.os, "replace", spy)
    return observed


# --------------------------------------------------------------------------- #
# HIGH: the SARIF is published atomically
# --------------------------------------------------------------------------- #


def test_a_sarif_write_that_dies_mid_flight_leaves_no_zero_byte_file(tmp_path: Path) -> None:
    """The measured symptom: a reader found ``len == 0``, which is the truncate window.

    An in-place write opens the destination for writing (truncating it) and only then
    encodes; a write that fails at the encode leaves nothing behind. A CI step uploading
    that file to code scanning uploads an empty SARIF, which reads exactly like a
    repository with no findings.
    """

    out = tmp_path / "out"
    out.mkdir()
    sarif = out / "evaluation-report.sarif"
    previous = json.dumps({"version": "2.1.0", "runs": [{"marker": _TARGET_A}]}) + "\n"
    sarif.write_text(previous, encoding="utf-8")

    with pytest.raises(UnicodeEncodeError):
        sw.write_sarif_report(_unencodable_report(target_path=_TARGET_B), sarif)

    assert sarif.stat().st_size > 0, "the SARIF was truncated to zero bytes by a failed write"
    assert sarif.read_text(encoding="utf-8") == previous, "a failed write clobbered the previous SARIF"
    assert sorted(p.name for p in out.iterdir()) == [sarif.name], "a temp file was orphaned"


def test_the_sarif_is_published_with_a_single_swap_over_a_whole_previous_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reader racing the writer must find the old log or the new one, never a partial."""

    out = tmp_path / "out"
    out.mkdir()
    sarif = out / "evaluation-report.sarif"
    previous = json.dumps({"version": "2.1.0", "runs": [{"marker": _TARGET_A}]}) + "\n"
    sarif.write_text(previous, encoding="utf-8")

    observed = _replace_spy(monkeypatch)
    sw.write_sarif_report(_report(target_path=_TARGET_B), sarif)

    assert observed == [previous], "the SARIF was not published with exactly one atomic swap"
    parsed = json.loads(sarif.read_text(encoding="utf-8"))
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"][0]["ruleId"] == "GOV-SEC-001"
    assert sorted(p.name for p in out.iterdir()) == [sarif.name]


def test_a_sarif_destination_that_cannot_be_written_still_raises_oserror(tmp_path: Path) -> None:
    """The CLI maps OSError to exit 2 for ``--sarif-output``; the swap must not change that.

    A destination that is an existing directory is the shape an adopter actually types.
    The temp file must not survive the refusal either.
    """

    out = tmp_path / "out"
    out.mkdir()
    occupied = out / "evaluation-report.sarif"
    occupied.mkdir()

    with pytest.raises(OSError):
        sw.write_sarif_report(_report(), occupied)

    assert sorted(p.name for p in out.iterdir()) == [occupied.name], "a temp file was orphaned by the refusal"


# --------------------------------------------------------------------------- #
# MEDIUM: the JSON and the Markdown are published as one pair
# --------------------------------------------------------------------------- #


def _seed_pair(out: Path) -> None:
    """Publish a complete, consistent pair for ``_TARGET_A``."""

    out.mkdir(parents=True, exist_ok=True)
    rp.write_reports(_report(target_path=_TARGET_A), out)


def _pair_text(out: Path) -> tuple[str, str]:
    return (
        (out / "evaluation-report.json").read_text(encoding="utf-8"),
        (out / "evaluation-report.md").read_text(encoding="utf-8"),
    )


def _block_markdown_publish(monkeypatch: pytest.MonkeyPatch, md_path: Path) -> None:
    """Simulate a handle held on ``evaluation-report.md`` that blocks rename *and* write.

    This is the reported reproduction: a process holding the Markdown open in a mode
    that refuses both the rename onto it and an in-place rewrite. Both routes have to be
    blocked, because the publish step deliberately falls back to an in-place write when
    a rename conflict outlives its retry budget.
    """

    real_replace = os.replace
    real_write_text = Path.write_text

    def replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        if Path(dst) == md_path:
            raise PermissionError(errno.EACCES, "Access is denied", str(dst))
        real_replace(src, dst, *args, **kwargs)

    def write_text(self: Path, *args: Any, **kwargs: Any) -> int:
        if self == md_path:
            raise PermissionError(errno.EACCES, "Access is denied", str(self))
        return real_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rp.os, "replace", replace)
    monkeypatch.setattr(Path, "write_text", write_text)


def test_a_blocked_markdown_write_does_not_leave_a_new_json_beside_a_stale_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The headline: one directory must never hold two files describing two runs."""

    out = tmp_path / "out"
    _seed_pair(out)
    before_json, before_md = _pair_text(out)
    assert _TARGET_A in before_json and _TARGET_A in before_md

    _block_markdown_publish(monkeypatch, out / "evaluation-report.md")

    with pytest.raises(OSError):
        rp.write_reports(_report(target_path=_TARGET_B), out)

    after_json, after_md = _pair_text(out)
    assert _TARGET_B not in after_json, "the JSON advanced to a run whose Markdown never landed"
    assert (after_json, after_md) == (before_json, before_md), "the pair is no longer the previous run"
    assert sorted(p.name for p in out.iterdir()) == [
        "evaluation-report.json",
        "evaluation-report.md",
    ], "a temp or rollback file was orphaned"


def test_a_first_run_whose_markdown_is_blocked_leaves_no_orphan_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no previous pair, rolling back means deleting the JSON, not keeping a lone one.

    A directory holding only ``evaluation-report.json`` reads as a successful run to
    every consumer that looks for the machine-readable artifact first.
    """

    out = tmp_path / "out"
    out.mkdir()
    _block_markdown_publish(monkeypatch, out / "evaluation-report.md")

    with pytest.raises(OSError):
        rp.write_reports(_report(target_path=_TARGET_B), out)

    assert list(out.iterdir()) == [], "a failed run left a report behind with no counterpart"


def test_the_operator_is_told_when_the_pair_could_not_be_put_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When rollback is impossible the mixed pair survives, so the error has to say so.

    The CLI renders ``strerror``, so a generic "cannot write to --output-dir" would send
    the operator to a directory whose two files disagree, with nothing pointing at it.
    """

    out = tmp_path / "out"
    _seed_pair(out)
    json_path = out / "evaluation-report.json"
    md_path = out / "evaluation-report.md"

    real_replace = os.replace
    real_write_text = Path.write_text
    swaps = {"json": 0}

    def replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        dest = Path(dst)
        if dest == md_path:
            raise PermissionError(errno.EACCES, "Access is denied", str(dst))
        if dest == json_path:
            swaps["json"] += 1
            if swaps["json"] > 1:  # the rollback swap
                raise PermissionError(errno.EACCES, "Access is denied", str(dst))
        real_replace(src, dst, *args, **kwargs)

    def write_text(self: Path, *args: Any, **kwargs: Any) -> int:
        if self == md_path:
            raise PermissionError(errno.EACCES, "Access is denied", str(self))
        return real_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(rp.os, "replace", replace)
    monkeypatch.setattr(Path, "write_text", write_text)

    with pytest.raises(OSError) as caught:
        rp.write_reports(_report(target_path=_TARGET_B), out)

    detail = caught.value.strerror or ""
    assert "evaluation-report.json" in detail and "evaluation-report.md" in detail
    assert "different runs" in detail, f"the mixed pair was reported as a plain write failure: {detail!r}"
    # The message reaches the user, so it carries no host path and no account name (M-002).
    # Asserted on a separator-free marker: the two report basenames are the only names
    # allowed in it, and neither contains a separator to begin with.
    assert tmp_path.name not in detail
    assert "/" not in detail and "\\" not in detail, f"a host path leaked into the message: {detail!r}"
    # The state the message describes is the state on disk: JSON advanced, Markdown did not.
    after_json, after_md = _pair_text(out)
    assert _TARGET_B in after_json and _TARGET_A in after_md


def test_a_previous_json_that_could_not_be_read_is_never_deleted_by_the_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rolling back must not turn "I could not read it" into "so I removed it".

    The snapshot distinguishes *absent* from *unreadable*: a report directory can hold a
    file this kit did not write, and treating an unreadable one as absent would make the
    rollback delete it. The honest outcome is to leave it and say the pair is mixed.
    """

    out = tmp_path / "out"
    _seed_pair(out)
    json_path = out / "evaluation-report.json"
    md_path = out / "evaluation-report.md"

    real_read_bytes = Path.read_bytes

    def read_bytes(self: Path) -> bytes:
        if self == json_path:
            raise PermissionError(errno.EACCES, "Access is denied", str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    _block_markdown_publish(monkeypatch, md_path)

    with pytest.raises(OSError) as caught:
        rp.write_reports(_report(target_path=_TARGET_B), out)

    assert json_path.is_file(), "a file the kit could not read was deleted by the rollback"
    assert "different runs" in (caught.value.strerror or ""), "an unrecoverable pair was reported as a plain failure"
    assert _TARGET_B in json_path.read_text(encoding="utf-8")
    assert _TARGET_A in md_path.read_text(encoding="utf-8")


def test_a_markdown_that_cannot_be_staged_publishes_no_json_at_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both files are staged before either is published, so a full disk lands neither.

    Publishing the JSON first and then discovering there is no room for the Markdown is
    the same mixed pair, reached by a different route. Rolling that JSON back afterwards
    restores the same end state, but not the same guarantee: between the publish and the
    undo there is a window in which a CI step or a dashboard reads a JSON from a run that
    never completed. So the assertion is that the destination was never swapped at all,
    not merely that it holds the right bytes afterwards.

    The injection has to close both routes to the Markdown -- its temp file and the
    in-place write the path-length fallback would otherwise use -- because that is what a
    genuinely full disk does.
    """

    out = tmp_path / "out"
    _seed_pair(out)
    json_path = out / "evaluation-report.json"
    md_path = out / "evaluation-report.md"
    before_json, before_md = _pair_text(out)

    real_create = rp._create_temp_exclusive
    real_write_text = Path.write_text
    real_replace = os.replace
    swapped: list[str] = []

    def create(tmp: Path, text: str) -> None:
        if md_path.name in tmp.name:
            raise OSError(errno.ENOSPC, "No space left on device", str(tmp))
        real_create(tmp, text)

    def write_text(self: Path, *args: Any, **kwargs: Any) -> int:
        if self == md_path:
            raise OSError(errno.ENOSPC, "No space left on device", str(self))
        return real_write_text(self, *args, **kwargs)  # type: ignore[arg-type]

    def replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        swapped.append(Path(dst).name)
        real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(rp, "_create_temp_exclusive", create)
    monkeypatch.setattr(Path, "write_text", write_text)
    monkeypatch.setattr(rp.os, "replace", replace)

    with pytest.raises(OSError):
        rp.write_reports(_report(target_path=_TARGET_B), out)

    assert swapped == [], f"a report was published and then undone rather than never published: {swapped}"
    assert _pair_text(out) == (before_json, before_md), "the JSON published before the Markdown was staged"
    assert sorted(p.name for p in out.iterdir()) == [json_path.name, md_path.name]


def test_a_report_that_cannot_be_encoded_touches_neither_file(tmp_path: Path) -> None:
    """Text that will not encode fails at the staging step, before anything is published."""

    out = tmp_path / "out"
    _seed_pair(out)
    before = _pair_text(out)

    with pytest.raises(UnicodeEncodeError):
        rp.write_reports(_unencodable_report(target_path=_TARGET_B), out)

    assert _pair_text(out) == before
    assert sorted(p.name for p in out.iterdir()) == ["evaluation-report.json", "evaluation-report.md"]


def test_a_markdown_renderer_that_raises_publishes_no_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both files are rendered before either is staged, so a renderer bug publishes neither.

    Fault-injected on the Markdown renderer, standing in for any exception raised while
    building the document. Rendering it only after the JSON has landed is how a single
    renderer bug turns into a directory whose two files disagree.
    """

    out = tmp_path / "out"
    _seed_pair(out)
    before = _pair_text(out)

    real_replace = os.replace
    swapped: list[str] = []

    def replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
        swapped.append(Path(dst).name)
        real_replace(src, dst, *args, **kwargs)

    def boom(*args: Any, **kwargs: Any) -> str:
        raise ValueError("markdown renderer blew up")

    monkeypatch.setattr(rp.os, "replace", replace)
    monkeypatch.setattr(rp, "_markdown_report_text", boom)

    with pytest.raises(ValueError):
        rp.write_reports(_report(target_path=_TARGET_B), out)

    assert swapped == [], f"a report was published before the pair was known to render: {swapped}"
    assert _pair_text(out) == before
    assert sorted(p.name for p in out.iterdir()) == ["evaluation-report.json", "evaluation-report.md"]


def test_the_ordinary_run_still_publishes_both_files_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pairing must not cost either file its own single-swap publish."""

    out = tmp_path / "out"
    _seed_pair(out)
    before_json, before_md = _pair_text(out)

    observed = _replace_spy(monkeypatch)
    json_path, md_path = rp.write_reports(_report(target_path=_TARGET_B), out)

    assert observed == [before_json, before_md], "a report was published without a single atomic swap"
    assert (json_path, md_path) == (out / "evaluation-report.json", out / "evaluation-report.md")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["target_path"] == _TARGET_B
    assert _TARGET_B in md_path.read_text(encoding="utf-8")
    assert sorted(p.name for p in out.iterdir()) == ["evaluation-report.json", "evaluation-report.md"]


def test_write_reports_creates_a_missing_output_directory(tmp_path: Path) -> None:
    """``--output-dir`` naming a directory that does not exist yet still works."""

    out = tmp_path / "nested" / "out"
    json_path, md_path = rp.write_reports(_report(), out)

    assert json.loads(json_path.read_text(encoding="utf-8"))["contract_version"] == "reports/2.0"
    assert md_path.read_text(encoding="utf-8").startswith("# OSS Policy Kit - evaluation report")


# --------------------------------------------------------------------------- #
# LOW: the drift table keeps bracketed fragments of control ids
# --------------------------------------------------------------------------- #

_BRACKETED_ID = "[bold]GOV-SEC-001"
_BRACKETED_BEFORE = "[green]pass"
_BRACKETED_AFTER = "[red]fail"
_BRACKETED_IMPROVED = "[dim]CI-PIN-008"
_BRACKETED_NEW = "[i]NEW-CTL-001"
_BRACKETED_REMOVED = "[u]OLD-CTL-002"
_BRACKETED_WAIVER = "[b]WAV-003"


def _bracketed_drift() -> DriftReport:
    """A drift report whose ids carry Rich-tag-shaped fragments.

    Control ids are read out of whatever two report files the caller diffed, so they are
    as attacker-shaped -- or as merely unlucky -- as any other user-controlled value.
    """

    return DriftReport(
        before_path="before.json",
        after_path="after.json",
        before_kit_version="10.0.6",
        after_kit_version="10.0.7",
        regressions=[
            ControlDelta(
                control_id=_BRACKETED_ID,
                title="Security policy present",
                before_status=_BRACKETED_BEFORE,
                after_status=_BRACKETED_AFTER,
                is_regression=True,
            )
        ],
        improvements=[
            ControlDelta(
                control_id=_BRACKETED_IMPROVED,
                title="Actions pinned",
                before_status="fail",
                after_status="pass",
                is_regression=False,
            )
        ],
        new_controls=[_BRACKETED_NEW],
        removed_controls=[_BRACKETED_REMOVED],
        expired_waivers=[_BRACKETED_WAIVER],
    )


_ANSI_SGR = re.compile(r"\x1b\[[0-9;]*m")


def _visible(text: str) -> str:
    """The characters an operator actually reads, with SGR colour codes removed.

    Under ``color=True`` Rich interleaves escape sequences with the text (it styles the
    digits of an id separately), so a raw substring check would fail on output that is
    perfectly correct on screen.
    """

    return _ANSI_SGR.sub("", text)


@pytest.mark.parametrize("color", [False, True], ids=["plain", "ansi"])
def test_the_drift_table_shows_control_ids_whole(color: bool) -> None:
    """Rich deletes ``[word]``, so the table named a control that never regressed."""

    text = _visible(rp.render_drift_report(_bracketed_drift(), "table", color=color))

    for value in (
        _BRACKETED_ID,
        _BRACKETED_BEFORE,
        _BRACKETED_AFTER,
        _BRACKETED_IMPROVED,
        _BRACKETED_NEW,
        _BRACKETED_REMOVED,
        _BRACKETED_WAIVER,
    ):
        assert value in text, f"the drift table swallowed part of {value!r}"


def test_the_drift_table_does_not_show_an_escape_the_operator_never_typed() -> None:
    """Escaping is for the renderer, not for the reader: no stray backslash may survive.

    Escaping an already-escaped value would print ``\\[bold]GOV-SEC-001`` -- a control id
    that matches nothing the operator can search for.
    """

    text = rp.render_drift_report(_bracketed_drift(), "table", color=False)

    assert "\\[" not in text, "a value was escaped twice and reached the operator with a backslash"


def test_the_drift_table_still_renders_its_own_labels_as_style() -> None:
    """Escaping the data must not escape the kit's own ``[red]``/``[green]`` markup.

    Closing tags are the tell: they appear only in the kit's own literals, never in the
    bracketed data above, so a leaked ``[/red]`` means the label stopped being style and
    became text.
    """

    plain = _visible(rp.render_drift_report(_bracketed_drift(), "table", color=False))
    assert "regression" in plain and "improve" in plain
    assert "[/red]" not in plain and "[/green]" not in plain, "the kit's own style tags leaked as literal text"

    ansi = rp.render_drift_report(_bracketed_drift(), "table", color=True)
    assert "\x1b[" in ansi, "the kit's own labels stopped being styled at all"


def test_markdown_and_json_drift_output_were_never_lossy_and_stay_that_way() -> None:
    """The other two formats keep the id whole; that is what made the table's loss silent."""

    drift = _bracketed_drift()

    md = rp.render_drift_report(drift, "markdown")
    assert _BRACKETED_ID in md and _BRACKETED_AFTER in md

    payload = json.loads(rp.render_drift_report(drift, "json"))
    assert payload["regressions"][0]["control_id"] == _BRACKETED_ID
    assert payload["regressions"][0]["after_status"] == _BRACKETED_AFTER
    assert payload["new_controls"] == [_BRACKETED_NEW]
