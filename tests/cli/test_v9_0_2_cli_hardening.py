"""CLI-level regression tests for the v9.0.2 hardening fixes (F2 unit).

- scaffold-evidence: a filesystem error on the user --target (here, ``.oss-policy-kit``
  pre-exists as a regular FILE so the ``.oss-policy-kit/evidence`` mkdir fails) must exit
  2 (usage/validation) with a clean error and NO raw traceback / path leak — previously it
  escaped as an unhandled OSError and crashed at exit 1, leaking the absolute path/username.
- profiles / recommend-profile: spot-check that the last-resort hardening did not change the
  happy path — both still exit 0 on a normal run.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()


def test_scaffold_evidence_target_with_file_collision_exits_2_no_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    # Pre-create .oss-policy-kit as a regular FILE so scaffold's
    # `.oss-policy-kit/evidence` mkdir(parents=True) fails with an OSError.
    (repo / ".oss-policy-kit").write_text("not a directory\n", encoding="utf-8")

    result = runner.invoke(
        app,
        prepare_cli_args(
            [
                "scaffold-evidence",
                "--target",
                str(repo),
                "--platform",
                "github",
            ]
        ),
    )

    # Usage/validation error, not an internal crash and not a silent success.
    assert result.exit_code == 2, result.output
    # No raw traceback leaked to the user.
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    combined = (result.output or "") + (str(result.exception) if result.exception else "")
    assert "Traceback" not in combined
    assert "cannot write output" in combined
    # The absolute target path / username must not be echoed (strerror only).
    assert str(repo) not in combined


def test_profiles_normal_run_still_exits_0() -> None:
    result = runner.invoke(app, prepare_cli_args(["profiles"]))
    assert result.exit_code == 0, result.output


def test_recommend_profile_normal_run_still_exits_0(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    result = runner.invoke(
        app,
        prepare_cli_args(["recommend-profile", "--target", str(repo)]),
    )
    assert result.exit_code == 0, result.output
