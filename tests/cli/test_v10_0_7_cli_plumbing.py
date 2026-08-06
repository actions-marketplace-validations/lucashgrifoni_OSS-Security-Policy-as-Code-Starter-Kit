"""v10.0.7 cli-plumbing lane: three CLI-boundary defects found by clean-room testing.

1. Rich markup ate the payload of the message. ``collect-evidence`` told a user whose
   optional extra was missing to run ``pip install 'oss-policy-kit'`` -- a command that
   installs nothing they are missing -- because ``[github]`` was interpolated into a
   markup string and parsed as a style tag. The same silent loss blanked the
   ``Repo slug: [not detected -- pass --repo where needed]`` line of the dry-run preview.
2. ``collect-evidence`` exited 3 ("Unexpected error") for that missing extra. Exit 3
   means the kit misbehaved; a dependency the user can install in one command is a
   usage error, exit 2.
3. ``oss-policy-kit --with-findings-summary evaluate ...`` exited 0 and wrote a report
   with an empty ``extensions`` object: the root callback parsed the flag and then
   discarded it because a subcommand was named.

Every assertion here fails when its fix is reverted (mutation-tested).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from oss_policy_kit.cli.common import markup_safe, prepare_cli_args
from oss_policy_kit.cli.main import app

runner = CliRunner()

#: Wide enough that the assertions below never straddle a Rich soft-wrap. The console
#: width comes from ``COLUMNS`` for the non-TTY streams a CliRunner provides.
_WIDE = "240"


def _invoke(args: list[str]) -> Result:
    return runner.invoke(app, prepare_cli_args(args))


def _flat(text: str) -> str:
    """Collapse Rich's soft-wrap whitespace so a phrase can be matched as one unit."""

    return " ".join(text.split())


def _github_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    return repo


# --------------------------------------------------------------------------------------
# 1 + 2: the missing optional extra keeps its install command, and exits 2 not 3
# --------------------------------------------------------------------------------------

#: platform -> (blocked third-party module, credential env, ``--repo`` value, extra name)
_MISSING_EXTRA_CASES = (
    ("github", "httpx", {"GITHUB_TOKEN": "t"}, "acme/widget", "github"),
    ("gitlab", "httpx", {"GITLAB_TOKEN": "t"}, "acme/widget", "gitlab"),
    (
        "azure",
        "httpx",
        {"AZURE_DEVOPS_ORG": "acme", "AZURE_DEVOPS_TOKEN": "t"},
        "Proj/widget",
        "azure",
    ),
    ("aws", "boto3", {"AWS_CODEBUILD_PROJECT": "build"}, "", "aws"),
)


@pytest.mark.parametrize(("platform", "module", "env", "slug", "extra"), _MISSING_EXTRA_CASES)
def test_missing_optional_extra_exits_2_with_a_command_that_actually_installs_it(
    platform: str,
    module: str,
    env: dict[str, str],
    slug: str,
    extra: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real collector import guard runs; its hint must survive Rich rendering.

    ``sys.modules[module] = None`` makes the collector's own ``import httpx`` / ``import
    boto3`` raise ImportError, so this exercises the shipped code path rather than a
    hand-rolled stand-in.
    """

    monkeypatch.setenv("COLUMNS", _WIDE)
    monkeypatch.setitem(sys.modules, module, None)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    args = ["collect-evidence", "--target", str(tmp_path), "--platform", platform]
    if slug:
        args += ["--repo", slug]
    result = _invoke(args)
    flat = _flat(result.output)

    # exit 2: a dependency the user can install is not an internal fault.
    assert result.exit_code == 2, result.output
    assert "Unexpected error" not in flat
    assert "Error:" in flat
    # the extra marker is the whole point of the message -- Rich must not eat it.
    assert f"pip install 'oss-policy-kit[{extra}]'" in flat


def test_dry_run_preview_shows_the_bracketed_not_detected_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The undetected-slug placeholder is bracketed, so it was rendered as nothing."""

    monkeypatch.setenv("COLUMNS", _WIDE)
    monkeypatch.delenv("GITLAB_PROJECT", raising=False)
    result = _invoke(["collect-evidence", "--target", str(tmp_path), "--platform", "gitlab", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "[not detected -- pass --repo where needed]" in _flat(result.output)


def test_markup_safe_keeps_bracketed_text_and_leaves_plain_text_alone() -> None:
    """Direct guard on the helper every call site now routes through."""

    from rich.console import Console

    hint = markup_safe("pip install 'oss-policy-kit[github]'")
    console = Console(width=200, force_terminal=False)
    with console.capture() as cap:
        console.print(f"hint: {hint}")
    assert "oss-policy-kit[github]" in cap.get()
    assert markup_safe("no brackets here") == "no brackets here"


# --------------------------------------------------------------------------------------
# 3: --with-findings-summary before the subcommand
# --------------------------------------------------------------------------------------


def _evaluate_args(repo: Path, out: Path) -> list[str]:
    return [
        "--target",
        str(repo),
        "--profile",
        "github-level-1",
        "--output-dir",
        str(out),
        "--fail-on",
        "none",
        "--quiet",
    ]


def test_root_position_with_findings_summary_is_honoured(tmp_path: Path) -> None:
    """The requested block is present -- previously exit 0 with ``extensions == {}``."""

    repo = _github_repo(tmp_path)
    out = tmp_path / "out"
    result = _invoke(["--with-findings-summary", "evaluate", *_evaluate_args(repo, out)])

    assert result.exit_code == 0, result.output
    payload = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    assert "findings_summary" in payload["extensions"], "the flag was parsed and then dropped"


def test_root_position_flag_matches_the_subcommand_placement(tmp_path: Path) -> None:
    """Root placement and subcommand placement produce the same extensions block."""

    repo = _github_repo(tmp_path)
    out_root = tmp_path / "root"
    out_sub = tmp_path / "sub"
    r_root = _invoke(["--with-findings-summary", "evaluate", *_evaluate_args(repo, out_root)])
    r_sub = _invoke(["evaluate", *_evaluate_args(repo, out_sub), "--with-findings-summary"])

    assert r_root.exit_code == r_sub.exit_code == 0
    root_ext = json.loads((out_root / "evaluation-report.json").read_text(encoding="utf-8"))["extensions"]
    sub_ext = json.loads((out_sub / "evaluation-report.json").read_text(encoding="utf-8"))["extensions"]
    assert root_ext == sub_ext


def test_compatibility_usage_without_a_subcommand_still_honours_the_flag(tmp_path: Path) -> None:
    """Guard on the relocation: no subcommand means nothing moves, and root still honours it."""

    repo = _github_repo(tmp_path)
    out = tmp_path / "out"
    args = ["--with-findings-summary", *_evaluate_args(repo, out)]
    assert prepare_cli_args(list(args)) == args

    result = _invoke(args)
    assert result.exit_code == 0, result.output
    payload = json.loads((out / "evaluation-report.json").read_text(encoding="utf-8"))
    assert "findings_summary" in payload["extensions"]


def test_root_position_flag_on_a_command_that_cannot_honour_it_exits_2() -> None:
    """``profiles`` cannot embed a findings summary; silently ignoring it was the bug."""

    result = _invoke(["--with-findings-summary", "profiles", "--format", "json"])
    assert result.exit_code == 2, result.output


def test_relocation_leaves_a_correctly_placed_flag_where_it_is() -> None:
    args = ["evaluate", "--target", "repo", "--with-findings-summary"]
    assert prepare_cli_args(list(args)) == args


def test_relocation_does_not_steal_a_preceding_options_value() -> None:
    """``--profile --with-findings-summary`` is that option's value, not a misplaced flag."""

    args = ["--profile", "--with-findings-summary", "evaluate", "--target", "repo"]
    assert prepare_cli_args(list(args)) == args


def test_relocation_preserves_the_leading_path_dispatch() -> None:
    """The bare-path dispatch that ``prepare_cli_args`` already owned is untouched."""

    args = ["./repo", "--profile", "github-level-1", "--with-findings-summary"]
    assert prepare_cli_args(list(args)) == ["evaluate", *args]
