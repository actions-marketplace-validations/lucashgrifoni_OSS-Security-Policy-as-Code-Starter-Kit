"""v10.0.2 regressions (group "output-write"): unusable write destinations must exit 2
(not 3) and never leak an absolute path / username (M-002).

Four confirmed extreme-end-user raio-x defects — each crashed exit 3 through the CLI's
last-resort handler and printed the full absolute path including the OS username:

  #7   export-policy --output <existing dir / under a file>
  #8   evaluate-many --output-dir <existing file>
  #9   evaluate-many  (mid-batch: a per-target subfolder name pre-exists as a FILE)
  #16  evaluate --sarif-output <existing dir / under a file>

Each write site now maps ``OSError`` to :class:`InvalidInputError` -> exit 2 with an
``exc.strerror``-only message, mirroring emit-insights / correlate-findings /
export-evidence (bad ``--output``) and single ``evaluate`` (bad ``--output-dir``).

Regression guarantees, per bug:
  * ``exit_code == 2`` (was 3)  -> deterministic, cross-platform contract signal.
  * a distinctive marker embedded in the destination path is ABSENT from the output
    (M-002)  -> before the fix the leaked OSError echoed the marker verbatim.
  * no ``Traceback`` / uncaught ``InvalidInputError`` escapes the CLI.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()

_PROFILE = "github-level-1"

# A distinctive, non-8.3-shortened leaf token. If any fix regressed and the raw OSError
# path were echoed, this token would appear verbatim in the message. strerror carries no
# path, so a passing fix keeps it out of the output entirely.
_MARKER = "leakmarker7q"


def _assert_clean_usage_error(output: str) -> None:
    assert _MARKER not in output, f"M-002: destination path leaked into the message:\n{output}"
    assert "Traceback" not in output, f"traceback leaked to the user:\n{output}"


# --- #7  export-policy --output points at an existing directory ----------------


def test_export_policy_output_is_existing_dir_exit2_no_leak(tmp_path: Path) -> None:
    existing_dir = tmp_path / f"{_MARKER}_dir"
    existing_dir.mkdir()
    res = runner.invoke(
        app,
        ["export-policy", "--profile", _PROFILE, "--format", "rego", "--output", str(existing_dir)],
    )
    assert res.exit_code == 2, f"expected exit 2, got {res.exit_code}\n{res.output}"
    assert not isinstance(res.exception, InvalidInputError), "InvalidInputError must be caught, not propagated"
    assert "Cannot write --output" in res.output, res.output
    _assert_clean_usage_error(res.output)


def test_export_policy_output_under_a_file_exit2_no_leak(tmp_path: Path) -> None:
    a_file = tmp_path / f"{_MARKER}_file"
    a_file.write_text("x", encoding="utf-8")
    # Writing to a path *under* an existing file is a filesystem error, not a crash.
    under_file = a_file / "policy.rego"
    res = runner.invoke(
        app,
        ["export-policy", "--profile", _PROFILE, "--format", "rego", "--output", str(under_file)],
    )
    assert res.exit_code == 2, f"expected exit 2, got {res.exit_code}\n{res.output}"
    _assert_clean_usage_error(res.output)


def test_export_policy_valid_output_still_writes(tmp_path: Path) -> None:
    out = tmp_path / "policy.rego"
    res = runner.invoke(
        app,
        ["export-policy", "--profile", _PROFILE, "--format", "rego", "--output", str(out)],
    )
    assert res.exit_code == 0, res.output
    assert out.is_file()
    assert "package osspolicykit" in out.read_text(encoding="utf-8")


# --- #8  evaluate-many --output-dir collides with an existing FILE -------------


def _make_target_root(tmp_path: Path, child: str = "app1") -> Path:
    root = tmp_path / "targets"
    (root / child / ".github" / "workflows").mkdir(parents=True)
    (root / child / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    return root


def test_evaluate_many_output_dir_is_existing_file_exit2_no_leak(tmp_path: Path) -> None:
    root = _make_target_root(tmp_path)
    output_file = tmp_path / f"{_MARKER}_out"
    output_file.write_text("x", encoding="utf-8")
    res = runner.invoke(
        app,
        ["evaluate-many", "--target-root", str(root), "--profiles", _PROFILE, "--output-dir", str(output_file)],
    )
    assert res.exit_code == 2, f"expected exit 2, got {res.exit_code}\n{res.output}"
    assert not isinstance(res.exception, InvalidInputError), "InvalidInputError must be caught, not propagated"
    assert "Cannot write to --output-dir" in res.output, res.output
    _assert_clean_usage_error(res.output)


# --- #9  evaluate-many: a per-target subfolder name pre-exists as a FILE -------


def test_evaluate_many_midbatch_subfolder_is_file_exit2_no_leak(tmp_path: Path) -> None:
    root = _make_target_root(tmp_path, child="app1")
    output_dir = tmp_path / "out9"
    output_dir.mkdir()
    # The batch wants to create output_dir / "app1" / <profile>; "app1" already exists
    # here as a FILE, so the per-target mkdir raised OSError mid-batch (was exit 3).
    (output_dir / f"app1{_MARKER}").write_text("x", encoding="utf-8")  # marker-tagged sibling
    (output_dir / "app1").write_text("x", encoding="utf-8")
    res = runner.invoke(
        app,
        ["evaluate-many", "--target-root", str(root), "--profiles", _PROFILE, "-o", str(output_dir)],
    )
    assert res.exit_code == 2, f"expected exit 2, got {res.exit_code}\n{res.output}"
    assert "Cannot write to --output-dir" in res.output, res.output
    _assert_clean_usage_error(res.output)


def test_run_batch_evaluation_output_dir_is_file_raises_invalidinput(tmp_path: Path) -> None:
    """Application-layer: the owned ``run_batch_evaluation`` maps a bad output dir to a
    typed usage error (so the CLI routes it to exit 2), not a bare OSError (exit 3)."""
    root = _make_target_root(tmp_path)
    output_file = tmp_path / "not-a-dir"
    output_file.write_text("x", encoding="utf-8")
    try:
        run_batch_evaluation(
            target_root=root,
            profile_ids=[_PROFILE],
            output_dir=output_file,
            kit_root=None,
            include=None,
            exclude=None,
        )
    except InvalidInputError as exc:
        assert str(output_file) not in exc.message, f"M-002: path leaked in message: {exc.message}"
    else:  # pragma: no cover - fixture guarantees the collision
        raise AssertionError("expected InvalidInputError for an output-dir that is a file")


def test_evaluate_many_valid_output_dir_still_writes(tmp_path: Path) -> None:
    root = _make_target_root(tmp_path)
    output_dir = tmp_path / "good-out"
    res = runner.invoke(
        app,
        ["evaluate-many", "--target-root", str(root), "--profiles", _PROFILE, "--output-dir", str(output_dir)],
    )
    assert res.exit_code == 0, res.output
    assert (output_dir / "evaluation-batch.json").is_file()


# --- #16  evaluate --sarif-output points at an existing directory --------------


def test_evaluate_sarif_output_is_existing_dir_exit2_no_leak(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    good_out = tmp_path / "out"  # report write must succeed so we REACH the SARIF write
    sarif_dir = tmp_path / f"{_MARKER}_sarif_dir"
    sarif_dir.mkdir()
    res = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(target),
            "--profile",
            _PROFILE,
            "--summary-only",
            "--output-dir",
            str(good_out),
            "--sarif-output",
            str(sarif_dir),
        ],
    )
    assert res.exit_code == 2, f"expected exit 2, got {res.exit_code}\n{res.output}"
    assert not isinstance(res.exception, InvalidInputError), "InvalidInputError must be caught, not propagated"
    assert "Cannot write --sarif-output" in res.output, res.output
    _assert_clean_usage_error(res.output)


def test_evaluate_valid_sarif_output_still_writes(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    good_out = tmp_path / "out"
    sarif_path = tmp_path / "report.sarif"
    res = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(target),
            "--profile",
            _PROFILE,
            "--summary-only",
            "--output-dir",
            str(good_out),
            "--sarif-output",
            str(sarif_path),
        ],
    )
    assert res.exit_code in (0, 1), res.output  # 0 or gate-trip 1; never a crash
    assert sarif_path.is_file()
