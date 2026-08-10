"""The shared CLI helpers, on the paths every command depends on but no test took.

These are small functions used by all 23 commands: how a path is shown, how an unexpected
exception becomes an exit code, how text reaches a stderr whose codepage cannot encode it.
Their failure modes are the ones that leak a home directory into a shareable report or turn
a clean error into a traceback, and several had never been executed.

One of them is dormant rather than untested. `PROFILE_DIRECTORY_ALIASES` has been empty
since v10.0.0 removed the CRA alias, so the deprecation warning cannot fire on any real
input. The mechanism is deliberately data-driven, so the test here injects an alias: what
is verified is that the next deprecation will actually warn, which is the only claim the
code still makes.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path
from typing import Any

import pytest
import typer
import yaml

from oss_policy_kit.cli import common
from oss_policy_kit.domain.errors import InvalidInputError

# --------------------------------------------------------------------------- #
# display_path -- the M-002 leak guard
# --------------------------------------------------------------------------- #


def test_empty_value_is_returned_unchanged() -> None:
    """An empty string is not a path; Path("") would become "." and invent a location."""

    assert common.display_path("") == ""


def test_relative_paths_are_shown_as_typed(tmp_path: Path) -> None:
    """Relative paths carry no host information, so shortening them only loses context."""

    assert common.display_path(".github/workflows/ci.yml") == ".github/workflows/ci.yml"


def test_an_absolute_path_that_cannot_be_resolved_degrades_to_its_basename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Falling back to the full absolute path here would leak exactly what this guards."""

    target = tmp_path / "deep" / "secret-repo" / "SECURITY.md"
    real = Path.resolve

    def _resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        if self.name == "SECURITY.md":
            raise OSError(errno.EIO, "I/O error")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", _resolve)

    shown = common.display_path(str(target))

    assert shown == "SECURITY.md"
    assert "secret-repo" not in shown


# --------------------------------------------------------------------------- #
# exit codes
# --------------------------------------------------------------------------- #


def _unicode_error() -> UnicodeDecodeError:
    return UnicodeDecodeError("utf-8", b"\xff\xfe", 0, 1, "invalid start byte")


@pytest.mark.parametrize(
    "exc",
    [
        OSError(errno.ENOENT, "No such file"),
        RecursionError("maximum recursion depth exceeded"),
        _unicode_error(),
        yaml.YAMLError("could not find expected ':'"),
        ValueError("Exceeds the limit (4300 digits) for integer string conversion"),
    ],
    ids=["oserror", "recursion", "unicode", "yaml", "int-limit"],
)
def test_unreadable_input_exits_2_not_3(exc: BaseException) -> None:
    """Exit 2 is "your input was wrong"; 3 is "the kit broke". Adopters gate on the difference."""

    with pytest.raises(typer.Exit) as excinfo:
        common.exit_for_unexpected(exc)

    assert excinfo.value.exit_code == 2


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("internal invariant broken"),
        # Deliberately NOT bad input: a bare ValueError here has nothing proving it came
        # from a file, and relabelling a defect as the adopter's fault is what exit 3
        # exists to prevent. See is_bad_input's docstring.
        ValueError("some internal conversion failed"),
        InvalidInputError("a kit-raised error still means the kit decided to stop"),
    ],
    ids=["runtime", "bare-valueerror", "kit-error"],
)
def test_a_genuine_internal_error_exits_3(exc: BaseException) -> None:
    with pytest.raises(typer.Exit) as excinfo:
        common.exit_for_unexpected(exc)

    assert excinfo.value.exit_code == 3


def test_the_error_text_reaches_stderr_without_a_traceback(capsys: pytest.CaptureFixture[str]) -> None:
    """v10.0.1 shipped because this printed a traceback with an absolute path in it."""

    with pytest.raises(typer.Exit):
        common.exit_for_unexpected(OSError(errno.ENOENT, "No such file"))

    captured = capsys.readouterr()
    assert "could not be read" in captured.err
    assert "Traceback" not in captured.err


# --------------------------------------------------------------------------- #
# stderr that cannot encode what it is handed
# --------------------------------------------------------------------------- #


class _NarrowStderr:
    """A stderr whose text layer rejects non-ASCII, like a cp1252 console."""

    def __init__(self, *, has_buffer: bool = True) -> None:
        self.buffer = _ByteSink() if has_buffer else None
        if not has_buffer:
            del self.buffer

    def write(self, text: str) -> int:
        text.encode("ascii")  # raises UnicodeEncodeError on a symbol
        return len(text)


class _ByteSink:
    def __init__(self) -> None:
        self.written = b""
        self.flushes = 0

    def write(self, data: bytes) -> int:
        self.written += data
        return len(data)

    def flush(self) -> None:
        self.flushes += 1


def test_plain_text_goes_straight_through(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    common.write_stderr_text("ordinary ascii\n")

    assert "ordinary ascii" in capsys.readouterr().err


def test_a_symbol_the_console_cannot_encode_falls_back_to_utf8_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Losing the message entirely would hide the warning the symbol was decorating."""

    narrow = _NarrowStderr()
    monkeypatch.setattr(sys, "stderr", narrow)

    common.write_stderr_text("check \u2713 done\n")

    sink = narrow.buffer
    assert isinstance(sink, _ByteSink)
    assert sink.written.decode("utf-8") == "check \u2713 done\n"
    assert sink.flushes == 1


def test_without_a_byte_buffer_the_encoding_error_is_re_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """No fallback available is a real failure; swallowing it would drop output silently."""

    monkeypatch.setattr(sys, "stderr", _NarrowStderr(has_buffer=False))

    with pytest.raises(UnicodeEncodeError):
        common.write_stderr_text("check \u2713 done\n")


# --------------------------------------------------------------------------- #
# path-ish argument detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "token",
    ["repo/sub", "repo\\sub", ".", "..", "~/repo", ".hidden", "C:\\repo", "D:/repo"],
)
def test_tokens_that_look_like_paths(token: str) -> None:
    """Used to tell a mistyped subcommand from a path, so the error names the right problem."""

    assert common._looks_like_path(token) is True


@pytest.mark.parametrize("token", ["evaluate", "emit-vex", "scan_iac"])
def test_tokens_that_look_like_subcommands(token: str) -> None:
    assert common._looks_like_path(token) is False


def test_an_existing_bare_name_is_still_treated_as_a_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`oss-policy-kit evaluate` in a directory holding a file named `evaluate`."""

    monkeypatch.chdir(tmp_path)
    (tmp_path / "evaluate").mkdir()

    assert common._looks_like_path("evaluate") is True


# --------------------------------------------------------------------------- #
# the dormant deprecation mechanism
# --------------------------------------------------------------------------- #


def test_no_alias_is_configured_today_so_nothing_warns(capsys: pytest.CaptureFixture[str]) -> None:
    """v10.0.0 emptied the map; a warning firing now would be a false deprecation notice."""

    assert common.PROFILE_DIRECTORY_ALIASES == {}

    common._warn_deprecated_profile_alias("github-level-1")

    assert capsys.readouterr().err == ""


def test_an_injected_alias_does_warn_and_names_its_replacement(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The mechanism has to still work for the next deprecation, which is its only claim.

    Verified by injecting the data it is driven by rather than by waiting for a real alias
    to exist -- there is none, and the code would otherwise be unreachable and unverified.
    """

    monkeypatch.setitem(common.PROFILE_DIRECTORY_ALIASES, "old-profile-1", "new-profile-1")

    common._warn_deprecated_profile_alias("old-profile-1")

    err = capsys.readouterr().err
    assert "old-profile-1" in err
    assert "new-profile-1" in err
    assert "deprecated" in err.lower()
