"""Regression tests for the `evaluate` stdout/stderr output contract (UAT bucket cli-output).

Every test here runs the real ``python -m oss_policy_kit`` so stdout and stderr stay
separate streams; ``CliRunner.output`` merges them (Click 8.2+) and would hide exactly
the defects under test.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _subprocess_env(*, columns: str = "120") -> dict[str, str]:
    """Deterministic, colour-free environment so Rich wrapping cannot break assertions."""

    env = os.environ.copy()
    for key in ("PYTHONHOME", "PYTHONSTARTUP", "PYTHONBREAKPOINT", "PYTHONINSPECT", "PYTHONEXECUTABLE"):
        env.pop(key, None)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = columns
    env["LINES"] = "40"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def _run(argv: list[str], *, cwd: Path, columns: str = "120") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *argv],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_subprocess_env(columns=columns),
        stdin=subprocess.DEVNULL,
        timeout=180,
        check=False,
    )


def _plain(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _collapse(text: str) -> str:
    """Flatten Rich's soft wrapping so a multi-word phrase can be matched reliably."""

    return " ".join(_plain(text).split())


def _make_github_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    return repo


def _target_line(stdout: str) -> str:
    for line in _plain(stdout).splitlines():
        if line.startswith("Target:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"no 'Target:' line in summary stdout:\n{stdout}")


# --------------------------------------------------------------------------- #
# verbose-json: --format json must keep stdout machine-readable
# --------------------------------------------------------------------------- #


def test_json_verbose_keeps_stdout_parseable_json(tmp_path: Path) -> None:
    """`--format json --verbose` piped to `jq` must not die on interleaved prose.

    Both `--format` and `--verbose` promise stdout is the machine channel in json mode;
    emitting the per-control lines there made every JSON consumer fail.
    """

    repo = _make_github_repo(tmp_path)
    proc = _run(
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--format",
            "json",
            "--verbose",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(_plain(proc.stdout).strip())
    assert payload["profile_id"] == "github-level-1"
    assert "Result:" not in _plain(proc.stdout)
    assert "Result:" in _plain(proc.stderr)


def test_human_verbose_still_writes_control_lines_to_stdout(tmp_path: Path) -> None:
    """Human mode is the documented pipe-friendly home of the per-control lines; keep it."""

    repo = _make_github_repo(tmp_path)
    proc = _run(
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--verbose",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    assert "Result:" in _plain(proc.stdout)


# --------------------------------------------------------------------------- #
# summary-only-leak: privacy default and --include-absolute-path must be honoured
# --------------------------------------------------------------------------- #


def test_summary_only_target_line_is_sanitized_by_default(tmp_path: Path) -> None:
    """A pasted `--summary-only` summary must not expose the auditor's home directory.

    The target is passed RELATIVE so the assertion cannot pass by accident on a host
    whose temp path happens to contain no username (or a Windows 8.3 short name).
    """

    _make_github_repo(tmp_path)
    proc = _run(
        [
            "evaluate",
            "--target",
            "repo",
            "--profile",
            "github-level-1",
            "--summary-only",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    target = _target_line(proc.stdout)
    assert target == "repo", target
    assert "/" not in target and "\\" not in target


def test_summary_only_include_absolute_path_opt_in_still_works(tmp_path: Path) -> None:
    """Downstream tooling that needs the real path must still get it via the opt-in flag."""

    repo = _make_github_repo(tmp_path)
    proc = _run(
        [
            "evaluate",
            "--target",
            "repo",
            "--profile",
            "github-level-1",
            "--summary-only",
            "--include-absolute-path",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    target = _target_line(proc.stdout)
    assert Path(target).is_absolute(), target
    assert Path(target) == repo.resolve()


def test_summary_only_external_waiver_path_is_sanitized(tmp_path: Path) -> None:
    """The `--waivers` note echoed the resolved waiver path, leaking the same home directory."""

    _make_github_repo(tmp_path)
    waivers = tmp_path / "my-waivers.yaml"
    waivers.write_text("waivers: []\n", encoding="utf-8")
    proc = _run(
        [
            "evaluate",
            "--target",
            "repo",
            "--profile",
            "github-level-1",
            "--waivers",
            "my-waivers.yaml",
            "--summary-only",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 0, proc.stderr
    stdout = _collapse(proc.stdout)
    assert "Path: my-waivers.yaml" in stdout, stdout
    assert str(tmp_path) not in stdout


# --------------------------------------------------------------------------- #
# summary-only-drops: the stderr suppression must be documented
# --------------------------------------------------------------------------- #


def test_summary_only_help_documents_stderr_suppression() -> None:
    """`--summary-only` also acts as a partial `--quiet`; an undocumented one is a trap."""

    proc = _run(["evaluate", "--help"], cwd=ROOT, columns="200")

    assert proc.returncode == 0, proc.stderr
    help_text = _collapse(proc.stdout + proc.stderr)
    assert "silences the stderr file-write confirmations" in help_text, help_text


# --------------------------------------------------------------------------- #
# contract-normalize: normalise once, echo what the user typed
# --------------------------------------------------------------------------- #


def test_double_v_prefixed_contract_is_rejected(tmp_path: Path) -> None:
    """Only ONE optional leading 'v' is documented; 'vv2.0' silently passing is a fail-open."""

    _make_github_repo(tmp_path)
    proc = _run(
        [
            "evaluate",
            "--target",
            "repo",
            "--profile",
            "github-level-1",
            "--report-json-contract",
            "vv2.0",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 2, f"exit={proc.returncode}\n{proc.stdout}\n{proc.stderr}"


def test_contract_error_quotes_the_value_the_user_typed(tmp_path: Path) -> None:
    """An error quoting a value the operator never typed sends them hunting the wrong config."""

    _make_github_repo(tmp_path)
    proc = _run(
        [
            "evaluate",
            "--target",
            "repo",
            "--profile",
            "github-level-1",
            "--report-json-contract",
            "V1.0",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        cwd=tmp_path,
    )

    assert proc.returncode == 2, proc.stdout
    message = _collapse(proc.stderr)
    assert "'V1.0'" in message, message


def test_documented_contract_spellings_still_accepted(tmp_path: Path) -> None:
    """The documented normalisation (case, whitespace, one leading 'v') must not regress."""

    _make_github_repo(tmp_path)
    for value in ("2.0", "V2.0", " v2.0 "):
        proc = _run(
            [
                "evaluate",
                "--target",
                "repo",
                "--profile",
                "github-level-1",
                "--report-json-contract",
                value,
                "--output-dir",
                str(tmp_path / "out"),
                "--summary-only",
                "--format",
                "json",
            ],
            cwd=tmp_path,
        )
        assert proc.returncode == 0, f"{value!r} -> {proc.returncode}\n{proc.stderr}"
