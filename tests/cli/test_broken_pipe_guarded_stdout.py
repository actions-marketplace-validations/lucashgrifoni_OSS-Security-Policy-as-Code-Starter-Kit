"""Direct tests for the stdout proxy that makes `oss-policy-kit ... | head` exit cleanly.

The proxy was only ever exercised end-to-end, through a real pipe in a subprocess. That
proves the happy path but says nothing about the branches that decide *which* OSError is
a broken pipe, or that the stream really is disabled after the first one -- and a pipe
closing mid-write is not something an end-to-end test can schedule reliably.

Every test here asserts on the wrapped stream's own state, so a guard that stopped
guarding would fail rather than pass quietly.
"""

from __future__ import annotations

import errno
from typing import Any

import pytest

from oss_policy_kit.cli.main import (
    _BrokenPipeExit,
    _BrokenPipeGuardedStdout,
    _is_broken_pipe,
)


class _FakeStream:
    """A stdout stand-in that fails on demand and records what reached it."""

    def __init__(self, write_error: OSError | None = None, flush_error: OSError | None = None) -> None:
        self.write_error = write_error
        self.flush_error = flush_error
        self.written: list[str] = []
        self.flushes = 0
        self.encoding = "utf-8"

    def write(self, data: str) -> int:
        if self.write_error is not None:
            raise self.write_error
        self.written.append(data)
        return len(data)

    def flush(self) -> None:
        self.flushes += 1
        if self.flush_error is not None:
            raise self.flush_error


def _broken_pipe(code: int = errno.EPIPE) -> OSError:
    return OSError(code, "Broken pipe")


def test_write_passes_through_and_reports_the_byte_count() -> None:
    """With nothing broken, the proxy is transparent."""

    stream = _FakeStream()
    guarded = _BrokenPipeGuardedStdout(stream)

    assert guarded.write("hello") == 5
    assert stream.written == ["hello"]


def test_flush_passes_through() -> None:
    stream = _FakeStream()

    _BrokenPipeGuardedStdout(stream).flush()

    assert stream.flushes == 1


@pytest.mark.parametrize("code", sorted({errno.EPIPE, errno.EINVAL}))
def test_broken_pipe_write_raises_the_control_flow_signal(code: int) -> None:
    """Both errnos the classifier accepts unwind as ``_BrokenPipeExit``."""

    guarded = _BrokenPipeGuardedStdout(_FakeStream(write_error=_broken_pipe(code)))

    with pytest.raises(_BrokenPipeExit):
        guarded.write("x")


def test_the_signal_does_not_derive_from_exception() -> None:
    """A per-command ``except Exception`` must not be able to swallow the pipe signal.

    This is the whole reason the class derives from BaseException (Sonar python:S5709,
    marked won't-fix against this test).
    """

    assert issubclass(_BrokenPipeExit, BaseException)
    assert not issubclass(_BrokenPipeExit, Exception)


def test_only_the_first_broken_write_raises_and_later_writes_are_dropped() -> None:
    """One signal per process: the shutdown flush must not raise a second time."""

    stream = _FakeStream(write_error=_broken_pipe())
    guarded = _BrokenPipeGuardedStdout(stream)

    with pytest.raises(_BrokenPipeExit):
        guarded.write("first")

    assert guarded.write("second") == 0
    guarded.flush()
    assert stream.flushes == 0, "a disabled stream was still flushed"


def test_a_non_pipe_write_error_is_re_raised_unchanged() -> None:
    """ENOSPC is a real failure; turning it into a clean exit would hide a lost report."""

    original = OSError(errno.ENOSPC, "No space left on device")
    guarded = _BrokenPipeGuardedStdout(_FakeStream(write_error=original))

    with pytest.raises(OSError) as excinfo:
        guarded.write("x")

    assert excinfo.value is original


def test_broken_pipe_on_flush_disables_the_stream_without_raising() -> None:
    """A flush cannot unwind through interpreter shutdown, so it swallows instead."""

    stream = _FakeStream(flush_error=_broken_pipe())
    guarded = _BrokenPipeGuardedStdout(stream)

    guarded.flush()

    assert stream.flushes == 1
    assert guarded.write("after") == 0, "the stream stayed enabled after a broken-pipe flush"


def test_a_non_pipe_flush_error_is_re_raised() -> None:
    original = OSError(errno.ENOSPC, "No space left on device")
    guarded = _BrokenPipeGuardedStdout(_FakeStream(flush_error=original))

    with pytest.raises(OSError) as excinfo:
        guarded.flush()

    assert excinfo.value is original


def test_every_other_attribute_is_delegated() -> None:
    """Rich inspects the stream it prints to; the proxy must not hide those attributes."""

    stream = _FakeStream()
    guarded = _BrokenPipeGuardedStdout(stream)

    assert guarded.encoding == "utf-8"
    with pytest.raises(AttributeError):
        _ = guarded.not_a_real_attribute


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (errno.EPIPE, True),
        (errno.EINVAL, True),
        (errno.ENOSPC, False),
        (errno.EACCES, False),
        (None, False),
    ],
)
def test_is_broken_pipe_classifies_by_errno(code: int | None, expected: bool) -> None:
    """``EINVAL`` is included because that is what Windows reports for a closed pipe."""

    exc = OSError()
    exc.errno = code

    assert _is_broken_pipe(exc) is expected


def test_write_returns_what_the_wrapped_stream_returned() -> None:
    """The count is taken from the stream, not from ``len(data)``.

    A stream that reports a short write has to be reported honestly upward; inventing
    ``len(data)`` here would tell the caller everything landed when it did not.
    """

    class _ShortWriter(_FakeStream):
        def write(self, data: str) -> int:
            self.written.append(data)
            return 2

    guarded: Any = _BrokenPipeGuardedStdout(_ShortWriter())

    assert guarded.write("hello") == 2
