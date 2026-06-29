"""v9.0.2 hotfix regression: emit-insights wraps errors cleanly (no traceback leak).

Before the fix, ``emit-insights`` had no error handler: a bad ``--target`` (an
``InvalidInputError`` raised in the body) or an unwritable ``--output`` (an
``OSError`` from ``output.write_text``) escaped as a raw Python traceback at
exit 1, leaking the absolute site-packages path and the OS username.

After the fix both fail-close cleanly at exit 2 with a one-line message and no
traceback / no absolute path / no username leak. Run end-to-end via subprocess
so we exercise the real process exit and the real stderr text a user sees.
"""

from __future__ import annotations

import getpass
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).parents[2]


def _run_emit_insights(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "emit-insights", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def _assert_no_traceback(stderr: str) -> None:
    """A clean user-facing error: no Python traceback and no internal install path."""
    assert "Traceback" not in stderr, stderr
    assert "site-packages" not in stderr, stderr


def _assert_no_username_leak(stderr: str) -> None:
    """The OS username must never appear in a message the kit composes internally."""
    username = getpass.getuser()
    if username:
        assert username not in stderr, stderr


def test_bad_target_exits_2_no_traceback(tmp_path: Path) -> None:
    """A --target that is not a directory exits 2 cleanly, no traceback / no site-packages."""
    not_a_dir = tmp_path / "not_a_directory.txt"
    not_a_dir.write_text("i am a file, not a dir\n", encoding="utf-8")
    out = tmp_path / "insights.yml"

    res = _run_emit_insights("--target", str(not_a_dir), "--output", str(out))

    assert res.returncode == 2, (res.returncode, res.stderr)
    assert "is not a directory" in res.stderr
    _assert_no_traceback(res.stderr)
    assert not out.exists()


def test_unwritable_output_exits_2_no_path_or_username_leak(tmp_path: Path) -> None:
    """An --output whose parent does not exist exits 2 cleanly.

    The error the kit composes must surface ``exc.strerror`` only — no absolute
    path and no OS username (the v9.0.2 leak this hotfix closes).
    """
    # Parent directory does not exist -> the write cannot succeed (OSError).
    out = tmp_path / "missing_subdir" / "insights.yml"

    res = _run_emit_insights("--target", str(REPO), "--output", str(out))

    assert res.returncode == 2, (res.returncode, res.stderr)
    assert "cannot write output" in res.stderr
    _assert_no_traceback(res.stderr)
    _assert_no_username_leak(res.stderr)
    assert not out.exists()


@pytest.mark.parametrize("flag", ["--merge", "--validate"])
def test_unwritable_output_exits_2_for_merge_and_validate(tmp_path: Path, flag: str) -> None:
    """The fail-close path holds for the --merge and --validate code paths too."""
    out = tmp_path / "missing_subdir" / "insights.yml"

    res = _run_emit_insights("--target", str(REPO), flag, "--output", str(out))

    assert res.returncode == 2, (res.returncode, res.stderr)
    _assert_no_traceback(res.stderr)
    _assert_no_username_leak(res.stderr)
    assert not out.exists()
