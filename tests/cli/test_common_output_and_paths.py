"""Path display, stderr that cannot encode, and the summary block's optional sections.

`display_path` is the privacy boundary for everything the CLI prints. It shortens an absolute
path to something that does not carry the operator's home directory or account name, and the
cases that matter are the ones where it cannot do its usual job: an empty value, and a path
that cannot be resolved because the working directory was deleted underneath the process.

`write_stderr_text` exists because a Windows console on a legacy codepage raises
`UnicodeEncodeError` on characters the kit routinely prints. Falling back to the underlying
byte buffer keeps the message readable instead of replacing it with an encoding traceback --
and when there is no buffer to fall back to, the original error is re-raised rather than
swallowed, because silently dropping an error message is worse than failing loudly.

The summary sections below are optional by design: a run with no structural causes, no waiver
file, or `--quiet` must simply omit them, not print an empty heading.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from oss_policy_kit.cli import common

# --------------------------------------------------------------------------- #
# display_path
# --------------------------------------------------------------------------- #


def test_an_empty_value_is_returned_unchanged() -> None:
    """Nothing to shorten, and inventing a "." here would be a fabricated path."""

    assert common.display_path("") == ""


def test_a_relative_path_is_left_alone() -> None:
    assert common.display_path("out/evaluation-report.json") == "out/evaluation-report.json"


def test_a_path_that_cannot_be_resolved_degrades_to_its_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """`Path.resolve` raises when the working directory is gone; the basename still informs."""

    def _boom(_self: Path, *args: object, **kwargs: object) -> Path:
        raise OSError(2, "No such file or directory")

    monkeypatch.setattr(Path, "resolve", _boom)
    shown = common.display_path(str(Path("/srv/build/out/evaluation-report.json").absolute()))
    assert shown.endswith("evaluation-report.json")
    assert "srv" not in shown


# --------------------------------------------------------------------------- #
# stderr on a codepage that cannot encode
# --------------------------------------------------------------------------- #


class _NarrowStderr(io.TextIOBase):
    """A console that raises the way cp1252 does, with a byte buffer behind it."""

    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, text: str) -> int:
        raise UnicodeEncodeError("charmap", text, 0, 1, "cannot encode")


class _NarrowStderrNoBuffer(io.TextIOBase):
    """The same console with no byte buffer to fall back to."""

    def write(self, text: str) -> int:
        raise UnicodeEncodeError("charmap", text, 0, 1, "cannot encode")


def test_text_that_the_console_cannot_encode_is_written_as_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The message survives the codepage instead of becoming an encoding traceback."""

    stderr = _NarrowStderr()
    monkeypatch.setattr("sys.stderr", stderr)
    common.write_stderr_text("evaluation: 3 controls need review\n")
    assert b"need review" in stderr.buffer.getvalue()


def test_with_no_byte_buffer_the_encoding_error_is_re_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """Silently dropping an error message is worse than failing loudly."""

    monkeypatch.setattr("sys.stderr", _NarrowStderrNoBuffer())
    with pytest.raises(UnicodeEncodeError):
        common.write_stderr_text("anything\n")


def test_text_the_console_can_encode_is_written_normally(monkeypatch: pytest.MonkeyPatch) -> None:
    """The counterpart: without it, a helper that always used the buffer would pass above."""

    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    common.write_stderr_text("plain ascii\n")
    assert stderr.getvalue() == "plain ascii\n"


# --------------------------------------------------------------------------- #
# Deprecated profile aliases
# --------------------------------------------------------------------------- #


def test_a_deprecated_alias_warns_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The alias map is empty today (ADR-029 removed them), so the lookup is stubbed.

    The function is lookup-driven, so feeding it a map is exercising its contract, not
    pretending the kit still ships an alias.
    """

    monkeypatch.setattr(common, "PROFILE_DIRECTORY_ALIASES", {"old-name-1": "new-name-1"})
    common._warn_deprecated_profile_alias("old-name-1")
    err = capsys.readouterr().err
    assert "deprecated" in err
    assert "new-name-1" in err


def test_a_current_profile_id_warns_about_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    common._warn_deprecated_profile_alias("github-level-1")
    assert capsys.readouterr().err == ""


# --------------------------------------------------------------------------- #
# --include-absolute-path is the only thing that turns sanitising off
# --------------------------------------------------------------------------- #


def test_the_human_summary_is_sanitised_unless_the_flag_asks_otherwise() -> None:
    """`--summary-only` used to echo the auditor's home directory; the flag is the one switch."""

    from oss_policy_kit.domain.models import ExecutionReport

    report = ExecutionReport(
        schema_version="https://example/reports/2.0",
        generated_at="2026-08-11T00:00:00Z",
        kit_version="10.0.11",
        target_path=str(Path("/home/auditor/clients/acme").absolute()),
        profile_id="github-level-1",
        profile_title="T",
        summary_by_status={"pass": 1},
        results=[],
        operational_warnings=[],
        weighted_score=None,
        external_waiver_path=str(Path("/home/auditor/waivers.yaml").absolute()),
    )

    kept = common._sanitize_report_for_human_stdout(report, include_absolute_path=True)
    assert kept is report, "the flag must hand back the report untouched"

    scrubbed = common._sanitize_report_for_human_stdout(report, include_absolute_path=False)
    assert scrubbed.target_path != report.target_path
    assert "auditor" not in scrubbed.target_path
    assert scrubbed.external_waiver_path is not None
    assert "auditor" not in scrubbed.external_waiver_path
