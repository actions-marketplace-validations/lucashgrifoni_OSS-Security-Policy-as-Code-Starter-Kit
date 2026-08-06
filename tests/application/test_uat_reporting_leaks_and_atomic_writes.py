"""Regression: reporting-layer path leaks, table corruption, and non-atomic report writes.

Four confirmed defects, all in the shareable-artifact path:

- *redaction-positional*: ``_redact_path`` dropped a fixed number of leading path
  components. A target nested deeper than that kept real host directory names —
  including the OS account name — in a reference the report labels
  ``"redacted": true``. A field that claims to be redacted and is not is worse than
  no redaction at all, because a reviewer stops looking.
- *unc-leak*: a UNC (``\\\\server\\share\\...``) or bare-backslash-rooted evidence
  source was not recognized as rooted at all, so the full path and the file-server
  name shipped verbatim with ``"redacted": false``.
- *waiver-pipe*: an unescaped ``|`` in a waiver owner (or any other user-controlled
  cell) splits the Markdown controls row into extra columns, silently shifting every
  value after it into the wrong column for any human or parser reading the report.
- *concurrent*: the report writers truncated the destination in place, so an
  interrupted or concurrent write left a half-written ``evaluation-report.json`` on
  disk while the process still exited 0.

Synthetic roots only (no ``Users``/``home`` segment) so the public-hygiene scanner
does not flag this file.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.application import evidence_projection as ep
from oss_policy_kit.application import reporting as rp
from oss_policy_kit.application.drift import ControlDelta, DriftReport
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport, WaiverRecord

# Synthetic host roots. Both nest the fake account segment deeper than the five
# components the positional redaction used to drop.
_ACCOUNT = "acct-name"
_DEEP_WIN = f"Z:\\srv\\vol1\\data\\profiles\\{_ACCOUNT}\\repo\\SECURITY.md"
_DEEP_POSIX = f"/srv/vol1/data/profiles/{_ACCOUNT}/repo/.github/workflows/ci.yml"
_FILE_SERVER = "fileserver01"
_UNC = f"\\\\{_FILE_SERVER}\\team-share\\repo\\SECURITY.md"
_UNC_SHARE_ROOT = f"\\\\{_FILE_SERVER}\\team-share"
_BACKSLASH_ROOTED = "\\srv\\profiles\\" + _ACCOUNT + "\\repo\\SECURITY.md"


def _result(**over: Any) -> ControlResult:
    kwargs: dict[str, Any] = {
        "control_id": "GOV-SEC-001",
        "title": "Security policy present",
        "category": "governance",
        "status": ControlStatus.PASS,
        "profile": "github-level-1",
        "evidence_sources": [],
        "confidence": "high",
        "reason": "ok",
        "remediation": "keep",
    }
    kwargs.update(over)
    return ControlResult(**kwargs)


def _report(results: list[ControlResult], *, target_path: str = "repo") -> ExecutionReport:
    return ExecutionReport(
        schema_version="https://x/reports/2.0",
        generated_at="2026-08-06T00:00:00Z",
        kit_version="10.0.5",
        target_path=target_path,
        profile_id="github-level-1",
        profile_title="GitHub level 1",
        summary_by_status={"pass": len(results)},
        results=results,
        operational_warnings=[],
    )


# --------------------------------------------------------------------------- #
# redaction-positional
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("rooted", [_DEEP_WIN, _DEEP_POSIX, _BACKSLASH_ROOTED])
def test_deeply_nested_evidence_path_keeps_no_host_directory_name(rooted: str) -> None:
    """A report that says a reference is redacted must not still carry the account name."""

    value, redacted = ep._redact_path(rooted)

    assert redacted is True
    assert _ACCOUNT not in value, "OS account name survived a reference marked redacted"
    for host_dir in ("srv", "vol1", "data", "profiles", "repo"):
        assert host_dir not in value, f"host directory '{host_dir}' survived redaction"
    assert value.endswith(("SECURITY.md", "ci.yml"))
    assert "<redacted-absolute>" in value


def test_deeply_nested_evidence_path_redacted_in_json_and_markdown(tmp_path: Path) -> None:
    """The account name must not reach either shareable artifact through evidence bullets."""

    report = _report([_result(evidence_sources=[_DEEP_WIN, _DEEP_POSIX])])

    payload = rp.report_to_dict(report)
    refs = payload["controls"][0]["evidence"]["references"]
    assert refs and all(r["redacted"] is True for r in refs)
    assert _ACCOUNT not in json.dumps(payload)

    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(report, md)
    assert _ACCOUNT not in md.read_text(encoding="utf-8")


def test_relative_path_under_the_real_home_directory_is_redacted() -> None:
    """A drive-stripped path still leads with the account name; content, not position, decides."""

    chain = Path.home().parts[1:]
    if not chain:  # pragma: no cover - a home directory always has at least one segment
        pytest.skip("no usable home-directory chain on this host")
    relative = "/".join([*chain, "repo", "SECURITY.md"])

    value, redacted = ep._redact_path(relative)

    assert redacted is True
    assert chain[-1] not in value
    assert value.endswith("SECURITY.md")


def test_ordinary_relative_repo_path_is_left_alone() -> None:
    """Redaction must not vandalize the relative repo paths that make a report useful."""

    assert ep._redact_path(".github/workflows/ci.yml") == (".github/workflows/ci.yml", False)
    assert ep._redact_path("src/app.py") == ("src/app.py", False)


# --------------------------------------------------------------------------- #
# unc-leak
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("unc", [_UNC, _UNC_SHARE_ROOT])
def test_unc_evidence_reference_never_exposes_the_file_server(unc: str) -> None:
    """A UNC evidence source discloses internal infrastructure: server and share names."""

    ref = ep.classify_reference(unc)

    assert ref["redacted"] is True
    assert _FILE_SERVER not in ref["value"], "file-server name leaked verbatim"
    assert "team-share" not in ref["value"], "share name leaked verbatim"


def test_unc_evidence_path_absent_from_json_and_markdown_reports(tmp_path: Path) -> None:
    report = _report([_result(evidence_sources=[_UNC])])

    payload_text = json.dumps(rp.report_to_dict(report))
    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(report, md)

    for blob in (payload_text, md.read_text(encoding="utf-8")):
        assert _FILE_SERVER not in blob
        assert "team-share" not in blob


def test_include_absolute_path_still_restores_unc_evidence(tmp_path: Path) -> None:
    """The opt-in escape hatch must keep working for every rooted shape."""

    report = _report([_result(evidence_sources=[_UNC])])
    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(report, md, include_absolute_path=True)

    assert _UNC in md.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# waiver-pipe
# --------------------------------------------------------------------------- #


def _cells(row: str) -> list[str]:
    """Split a Markdown table row on unescaped pipes."""

    return [c.strip() for c in re.split(r"(?<!\\)\|", row)[1:-1]]


def test_pipe_in_user_controlled_cells_does_not_shift_the_controls_table(tmp_path: Path) -> None:
    """A '|' in a waiver owner silently shifts every later column into the wrong header."""

    waiver = WaiverRecord(
        control_id="GOV-SEC-001",
        justification="accepted",
        owner="sec|team",
        status="approved",
        expires_at=None,
        applies_to=None,
    )
    report = _report(
        [
            _result(
                category="gov|ernance",
                confidence="hi|gh",
                reason="a | b",
                remediation="c | d",
                waiver=waiver,
            )
        ]
    )
    md = tmp_path / "evaluation-report.md"
    rp.write_markdown_report(report, md)
    lines = md.read_text(encoding="utf-8").splitlines()

    header = next(line for line in lines if line.startswith("| ID |"))
    row = next(line for line in lines if line.startswith("| `GOV-SEC-001` |"))

    assert len(_cells(row)) == len(_cells(header)), "table row column count diverged from the header"
    # The owner must still be readable, and land in the Waiver column, not spill sideways.
    assert _cells(row)[-1] == "yes (sec\\|team)"


def test_pipe_in_drift_control_id_does_not_shift_the_drift_table() -> None:
    """Drift tables render ids read from an arbitrary report file; those are attacker-shaped too."""

    drift = DriftReport(
        before_path="before.json",
        after_path="after.json",
        before_kit_version="10.0.4",
        after_kit_version="10.0.5",
        regressions=[
            ControlDelta(
                control_id="GOV|SEC-001",
                title="t",
                before_status="PASS",
                after_status="FA|IL",
                is_regression=True,
            )
        ],
    )

    text = rp.render_drift_report(drift, "markdown")
    row = next(line for line in text.splitlines() if line.startswith("| `GOV"))

    assert len(_cells(row)) == 3


# --------------------------------------------------------------------------- #
# concurrent (atomic writes)
# --------------------------------------------------------------------------- #


def _unencodable_report() -> ExecutionReport:
    """A report whose text cannot be UTF-8 encoded, to interrupt a write mid-flight.

    A lone surrogate reaches ``reason`` whenever an evaluator echoes text decoded
    from a malformed source file, so this is the same failure shape a real
    interrupted write produces: the encoder raises *after* the destination has been
    opened for writing.
    """

    return _report([_result(reason="bad \ud800 text")])


@pytest.mark.parametrize("writer", ["json", "markdown"])
def test_failed_write_leaves_the_previous_report_intact(tmp_path: Path, writer: str) -> None:
    """A write that dies mid-flight must not leave a truncated report behind exit 0."""

    out = tmp_path / "out"
    out.mkdir()
    path = out / f"evaluation-report.{'json' if writer == 'json' else 'md'}"
    previous = "PREVIOUS-COMPLETE-REPORT"
    path.write_text(previous, encoding="utf-8")

    write = rp.write_json_report if writer == "json" else rp.write_markdown_report
    with pytest.raises(UnicodeEncodeError):
        write(_unencodable_report(), path)

    assert path.read_text(encoding="utf-8") == previous, "destination was truncated by a failed write"
    assert sorted(p.name for p in out.iterdir()) == [path.name], "temp file left behind after a failed write"


@pytest.mark.parametrize("writer", ["json", "markdown"])
def test_destination_is_swapped_in_one_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: str) -> None:
    """A concurrent reader must see the old report or the new one, never a half-written file."""

    out = tmp_path / "out"
    out.mkdir()
    path = out / f"evaluation-report.{'json' if writer == 'json' else 'md'}"
    previous = "PREVIOUS-COMPLETE-REPORT"
    path.write_text(previous, encoding="utf-8")

    observed: list[str] = []
    real_replace = os.replace

    def spy(src: Any, dst: Any) -> None:
        # State of the destination at the instant before the swap: a reader racing the
        # writer here must still find the whole previous report.
        observed.append(Path(dst).read_text(encoding="utf-8"))
        real_replace(src, dst)

    monkeypatch.setattr(rp.os, "replace", spy)

    write = rp.write_json_report if writer == "json" else rp.write_markdown_report
    write(_report([_result()]), path)

    assert observed == [previous], "report was not published with a single atomic swap"
    assert path.read_text(encoding="utf-8") != previous
    assert sorted(p.name for p in out.iterdir()) == [path.name]


# --------------------------------------------------------------------------------------
# Consequences of the redaction rewrite that no test claimed in either direction.
# Both are deliberate; they are pinned here so a later change has to argue with a test
# rather than discover them in a shared report.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["~/repo/SECURITY.md", "~\\repo\\SECURITY.md"],
    ids=["posix", "windows"],
)
def test_tilde_rooted_reference_is_redacted_to_its_leaf(value: str) -> None:
    """``~`` hides the account name, but not the layout of the machine behind it."""

    out = ep.classify_reference(value)

    assert out["redacted"] is True
    assert out["value"].endswith("SECURITY.md")
    assert "repo" not in out["value"]


def test_protocol_relative_reference_is_treated_as_a_share_not_a_url() -> None:
    """``//host/...`` fails closed: Windows accepts forward-slash UNC paths.

    Reading it as a protocol-relative URL would ship ``//internal-fileserver/share``
    verbatim. The reference is lost instead, which is the cheaper of the two errors.
    """

    out = ep.classify_reference("//example.com/policy.md")

    assert out["kind"] == "path"
    assert out["redacted"] is True
    assert "example.com" not in out["value"]

    # The escape hatch is a real scheme, and it still passes through untouched.
    explicit = ep.classify_reference("https://example.com/policy.md")
    assert explicit == {"kind": "url", "value": "https://example.com/policy.md", "redacted": False}


# --------------------------------------------------------------------------------------
# Atomicity must not cost reach: a sibling temp file makes the path longer than the
# destination, and Windows caps a path at 260 characters.
# --------------------------------------------------------------------------------------


def _capture_temp_name(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the basename of whatever ``_atomic_write_text`` swaps into place."""

    seen: list[str] = []
    real_replace = os.replace

    def spy(src: Any, dst: Any) -> None:
        seen.append(Path(src).name)
        real_replace(src, dst)

    monkeypatch.setattr(rp.os, "replace", spy)
    return seen


def test_temp_file_keeps_the_destination_name_when_the_path_has_room(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ordinary case stays atomic and stays debuggable."""

    seen = _capture_temp_name(monkeypatch)
    dest = tmp_path / "evaluation-report.json"

    rp._atomic_write_text(dest, "next\n")

    assert len(seen) == 1, "the write did not go through a single atomic swap"
    assert re.fullmatch(rf"\.{re.escape(dest.name)}\.[0-9a-f]{{8}}\.tmp", seen[0]), (
        f"the temp file dropped the destination name for no reason: {seen[0]}"
    )
    assert dest.read_text(encoding="utf-8") == "next\n"


def test_temp_file_shrinks_rather_than_overrunning_the_path_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A destination near MAX_PATH is still written, atomically, with no orphan.

    The descriptive temp name costs 14 characters over the destination, so a path in
    the 246-259 band would fail to create a temp file it could have written directly.
    Before the shrink, an ``--output-dir`` that used to work started failing exit 2.
    """

    # The budget is written out here rather than read from the module: a test that
    # derives its own fixture from the constant it is checking cannot catch a change
    # to that constant. This asserts the production value instead.
    limit = 259  # Windows MAX_PATH (260) less the terminating NUL
    assert limit == rp._MAX_TEMP_PATH, "the temp-path budget moved away from Windows MAX_PATH"

    name = "evaluation-report.json"
    seg = "nested-directory-segment"
    deep = tmp_path
    while len(str(deep / seg / name)) <= limit - 14:
        deep = deep / seg
    # Pad to land inside the band: the destination fits, the descriptive temp does not.
    pad = limit - 13 - len(str(deep / name))
    if pad > 0:
        deep = deep / ("p" * pad)
    deep.mkdir(parents=True, exist_ok=True)
    dest = deep / name
    assert len(str(dest)) <= limit, "fixture destination does not fit"
    assert len(str(dest)) + 14 > limit, "fixture is not in the interesting band"

    seen = _capture_temp_name(monkeypatch)
    rp._atomic_write_text(dest, '{"contract_version": "reports/2.0"}\n')

    assert json.loads(dest.read_text(encoding="utf-8")) == {"contract_version": "reports/2.0"}
    assert seen and name not in seen[0], "temp name did not shrink, so the path limit was overrun"
    assert re.fullmatch(r"\.[0-9a-f]{8}\.tmp", seen[0]), f"unexpected shrunk temp name: {seen[0]}"
    assert [p.name for p in deep.iterdir()] == [name], "a temp file was orphaned next to the report"
