"""A named pipe in the scanned tree must not stop the scan, and the stat must precede the open.

The file scanners read the head of every candidate file in a clone, and a clone is untrusted
content. `os.walk` puts every non-directory entry in `filenames`, a FIFO among them, and
opening a FIFO for reading blocks until some process opens the write end -- which for a file
committed by whoever wrote the repository is never. `Path.is_file()` is what keeps it out:
it answers from `stat()`, which does not open anything, and returns False for a FIFO.

That guard has been in both walkers since the feature shipped (`2cdf3e4`, 2026-05-09), so
this is confirmation of existing behaviour rather than a fix. What was missing was any test
of it: the guard's only coverage came from `rglob` yielding directories, and when the walkers
moved to `os.walk` -- which lists directories separately -- that test kept passing while
exercising nothing.

The ordering is the fragile part. The guard holds only while the `is_file()` check stays
BEFORE the read. Reordering them, or adding a read path that skips the check, reintroduces an
indefinite block, and a hanging test reads as a slow test until the job times out. So the scan
runs on a daemon thread here and the assertion is a deadline: it fails in seconds and names
itself, instead of burning the runner's timeout.

The portable half of this guard is
``test_an_entry_that_is_not_a_regular_file_is_skipped`` in the two scanner test modules, which
forces the same condition and dies under mutation on every platform. This file adds the real
thing, on the platforms that have it.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from oss_policy_kit.application import evaluators_fuzzing as fz
from oss_policy_kit.application import evaluators_webhook as wh

#: Generous next to a scan of three files, and four orders of magnitude under "forever".
_DEADLINE_SECONDS = 20.0

pytestmark = pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="os.mkfifo is POSIX-only; Windows has no filesystem entry that blocks on open this way",
)


def _tree_with_a_fifo(tmp_path: Path) -> Path:
    """A readable file, a FIFO, and a second readable file, all with scanned extensions.

    The FIFO sorts between the two so a walker that reads it stalls with work still ahead --
    a scan that stopped at the FIFO would otherwise be indistinguishable from one that
    finished early.
    """

    (tmp_path / "a_first.py").write_text("import atheris\n", encoding="utf-8")
    os.mkfifo(tmp_path / "m_pipe.py")  # type: ignore[attr-defined,unused-ignore]  # POSIX-only; the module skips elsewhere
    (tmp_path / "z_last.py").write_text("@app.post('/webhook')\n", encoding="utf-8")
    return tmp_path


def _finishes_within(work: object, seconds: float) -> bool:
    """Run *work* on a daemon thread and report whether it returned in time.

    A thread blocked on a FIFO cannot be interrupted, so it is left running as a daemon and
    the process exits without it. That is the price of failing fast instead of hanging.
    """

    done = threading.Event()

    def _run() -> None:
        try:
            work()  # type: ignore[operator]
        finally:
            done.set()

    threading.Thread(target=_run, daemon=True).start()
    return done.wait(seconds)


def test_the_fuzzing_scan_finishes_with_a_fifo_in_the_tree(tmp_path: Path) -> None:
    repo = _tree_with_a_fifo(tmp_path)
    assert _finishes_within(lambda: fz._has_fuzz_content(repo), _DEADLINE_SECONDS), (
        f"the fuzzing scan did not finish within {_DEADLINE_SECONDS}s with a FIFO in the tree. "
        "It is blocked opening the pipe, which means the is_file() check no longer runs before "
        "the read."
    )


def test_the_webhook_scan_finishes_with_a_fifo_in_the_tree(tmp_path: Path) -> None:
    repo = _tree_with_a_fifo(tmp_path)
    assert _finishes_within(lambda: wh._scan_signals(repo), _DEADLINE_SECONDS), (
        f"the webhook scan did not finish within {_DEADLINE_SECONDS}s with a FIFO in the tree. "
        "It is blocked opening the pipe, which means the is_file() check no longer runs before "
        "the read."
    )


def test_the_fifo_is_not_offered_to_the_reader_at_all() -> None:
    """The outcome above is the point, but this says why: the pipe never reaches a read."""

    import tempfile

    with tempfile.TemporaryDirectory() as raw:
        repo = _tree_with_a_fifo(Path(raw))
        for walker in (fz._iter_candidate_paths, wh._iter_candidate_paths):
            names = [p.name for p in walker(repo)]
            assert "m_pipe.py" not in names, f"{walker.__module__} offered the FIFO: {names}"
            assert "a_first.py" in names, f"{walker.__module__} stopped early: {names}"
