"""v10.0.7 m002-echo lane: a relative argument must come back relative.

Clean-room validation of the built wheel found the same shape in six commands: the
adopter typed ``--target .`` or ``--output-dir reports`` and the kit answered with the
fully-qualified path through their home directory. That is not what they asked for, it
is not something they can paste anywhere, and it carries their home directory and OS
account name into the terminal, the CI log, and the issue they open (M-002).

Covered here:

- ``init`` echoed the resolved target in ``--format json`` (the ``init-result/v1``
  contract) and in the human summary, long after ``actions.created`` was made relative.
- ``scaffold-evidence`` printed all eight written files fully qualified.
- ``evaluate`` printed ``Wrote <abs>/evaluation-report.json`` twice, a ``Reports: <abs>``
  footer, and the same for ``--sarif-output``.
- ``collect-evidence --dry-run`` printed the target, the output directory, and every
  previewed file fully qualified.
- A root option typed before the subcommand produced ``Provide a repository path as
  TARGET or via --target/-t`` while ``--target`` was visibly on the command line.
- ``scaffold-evidence``'s filesystem-error line escaped its detail twice, showing a
  backslash nobody typed in front of a bracket.
- Two error handlers in the same two files interpolated the ``OSError`` itself, and
  ``str(OSError)`` renders the offending filename: the same leak arriving by a different
  route, on the exact paths a failed ``init`` / ``scaffold-evidence`` prints.

Windows notes, because two traps live here. ``json.dumps`` doubles every backslash, so
``str(tmp_path) not in json.dumps(x)`` is vacuously true on this platform; and 8.3 short
paths (``LUCASG~1``) make a naive absolute-path assertion pass for the wrong reason.
Every leak assertion below therefore looks for a separator-free marker -- a distinctive
DIRECTORY NAME the fixture creates -- which survives both. ``COLUMNS`` is pinned wide so
a Rich soft-wrap can never split that marker and make an assertion pass by accident.

Every guard here was mutation-tested: the fix was reverted, the test was confirmed to
fail, and the fix was restored.
"""

from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from oss_policy_kit.cli import evidence as evidence_mod
from oss_policy_kit.cli.common import display_path, prepare_cli_args
from oss_policy_kit.cli.main import app

runner = CliRunner()

#: Wide enough that no assertion below straddles a Rich soft-wrap. For the non-TTY
#: streams a CliRunner provides, both Rich and the kit's own wrapper read ``COLUMNS``.
_WIDE = "240"

#: A separator-free directory name. If any resolved path reaches the user, this token
#: appears verbatim in the output; ``json.dumps`` cannot hide it behind doubled
#: backslashes and a short-path expansion cannot rewrite it.
_MARKER = "m002markerdirectory"


def _invoke(args: list[str]) -> Result:
    return runner.invoke(app, prepare_cli_args(args))


def _flat(text: str) -> str:
    """Collapse soft-wrap whitespace so a phrase can be matched as one unit."""

    return " ".join(text.split())


@pytest.fixture()
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A current directory whose name is the leak marker; commands run relative to it."""

    monkeypatch.setenv("COLUMNS", _WIDE)
    root = tmp_path / _MARKER
    root.mkdir()
    monkeypatch.chdir(root)
    return root


def _github_repo(root: Path, name: str = "acme-service") -> Path:
    repo = root / name
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    (repo / "README.md").write_text("# demo\n", encoding="utf-8")
    return repo


# ======================================================================================
# display_path: the one rule every call site below relies on
# ======================================================================================


def test_display_path_echoes_a_relative_value_exactly_as_given(workdir: Path) -> None:
    """No normalization, no resolution: the operator reads back what they typed."""

    assert display_path("acme-service") == "acme-service"
    assert display_path(".") == "."
    assert display_path("./nested/out") == "./nested/out"
    assert display_path(Path("out") / "report.json") == str(Path("out") / "report.json")


def test_display_path_reduces_an_absolute_value_under_the_cwd(workdir: Path) -> None:
    """Where an artifact landed is useful; everything above the cwd is not."""

    assert display_path(workdir / "acme-service") == "acme-service"
    assert display_path(workdir) == "."
    assert _MARKER not in display_path(workdir / "acme-service" / "out")


def test_display_path_degrades_outside_the_cwd_instead_of_leaking(workdir: Path) -> None:
    """The fallback holds the same line the relativization does."""

    outside = workdir.parent / "elsewhere" / "report.json"

    assert display_path(outside) == "report.json"
    assert display_path(outside, root=workdir.parent / "elsewhere") == "report.json"
    assert _MARKER not in display_path(workdir.parent / _MARKER / "x", root=workdir.parent)


# ======================================================================================
# init: the machine contract answered a relative --target with the account name
# ======================================================================================


def test_init_json_target_is_the_argument_the_user_typed(workdir: Path) -> None:
    """``init --target acme-service --format json`` must answer ``acme-service``."""

    _github_repo(workdir)
    result = _invoke(["init", "--target", "acme-service", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["target"] == "acme-service"
    assert not Path(payload["target"]).is_absolute()
    assert _MARKER not in json.dumps(payload), "the resolved target leaked into init's machine output"


def test_init_json_target_dot_stays_dot(workdir: Path) -> None:
    """``--target .`` is the exact case the defect names, and the easiest to get wrong."""

    _github_repo(workdir, name=".")  # writes the CI signal straight into the cwd
    result = _invoke(["init", "--target", ".", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["target"] == "."
    assert _MARKER not in json.dumps(payload)


def test_init_human_summary_target_line_is_relative(workdir: Path) -> None:
    """The human summary reads the same target back, for the same reason."""

    _github_repo(workdir)
    result = _invoke(["init", "--target", "acme-service"])

    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    assert "Target: acme-service" in flat
    assert _MARKER not in result.output


def test_init_dry_run_note_for_a_missing_target_quotes_the_typed_path(workdir: Path) -> None:
    """The note that tells the adopter to create the directory names the one they typed."""

    result = _invoke(["init", "--target", "not-created-yet", "--dry-run"])

    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    assert "Target directory does not exist yet: not-created-yet." in flat
    assert _MARKER not in result.output


def test_init_rejects_a_missing_target_without_naming_the_host(workdir: Path) -> None:
    """The exit-2 path echoes the argument too, and keeps its message."""

    result = _invoke(["init", "--target", "nope"])

    assert result.exit_code == 2, result.output
    flat = _flat(result.output)
    assert "--target path does not exist: nope." in flat
    assert _MARKER not in result.output


def test_init_filesystem_failure_names_the_reason_not_the_file(workdir: Path) -> None:
    """A failed write reported ``str(OSError)``, which carries the resolved filename.

    ``oss-policy-kit.yaml`` is a directory here, so the atomic replace fails with a real
    OS error whose ``filename``/``filename2`` are absolute.
    """

    repo = _github_repo(workdir)
    (repo / "oss-policy-kit.yaml").mkdir()

    result = _invoke(["init", "--target", "acme-service", "--force"])

    assert result.exit_code == 2, result.output
    assert "Error:" in result.output
    assert _MARKER not in result.output, "the OSError filename leaked the host path"


# ======================================================================================
# scaffold-evidence: eight written files, eight fully-qualified lines
# ======================================================================================


def test_scaffold_evidence_lists_every_file_relative_to_the_cwd(workdir: Path) -> None:
    """Each ``+`` line is a path the adopter can act on from where they are standing."""

    (workdir / "acme-service").mkdir()
    result = _invoke(["scaffold-evidence", "--target", "acme-service", "--platform", "github"])

    assert result.exit_code == 0, result.output
    assert _MARKER not in result.output, "the resolved evidence paths leaked into stdout"

    listed = [line.strip()[2:].strip() for line in result.stdout.splitlines() if line.startswith("  + ")]
    assert listed, result.stdout
    for entry in listed:
        assert not Path(entry).is_absolute(), entry
        assert Path(entry).as_posix().startswith("acme-service/.oss-policy-kit/evidence/"), entry
    assert any(e.endswith("branch-protection.json") for e in listed), listed


def test_scaffold_evidence_note_for_an_auto_created_target_echoes_the_argument(workdir: Path) -> None:
    """The "created missing --target directory" note is the same echo problem."""

    result = _invoke(["scaffold-evidence", "--target", "brand-new", "--platform", "github"])

    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    assert "created missing --target directory: brand-new" in flat
    assert _MARKER not in result.output


def test_scaffold_evidence_reports_an_uncreatable_target_without_the_host_path(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``str(OSError)`` renders the filename it was handed, which ``~`` expands to.

    The operator typed a tilde, not their home directory. Interpolating the exception put
    the expanded path -- account name and all -- into the message; ``strerror`` carries
    the reason the directory could not be created without carrying where it would have
    gone (M-002).
    """

    for var in ("USERPROFILE", "HOME"):
        monkeypatch.setenv(var, str(workdir))
    (workdir / "a-regular-file").write_text("not a directory\n", encoding="utf-8")

    result = _invoke(["scaffold-evidence", "--target", "~/a-regular-file/child", "--platform", "github"])

    assert result.exit_code == 2, result.output
    assert "Could not create --target directory" in _flat(result.output)
    assert _MARKER not in result.output, "the expanded home path leaked through the OSError"


def test_scaffold_evidence_filesystem_error_is_escaped_exactly_once(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bracketed strerror must reach the operator as they would see it in the shell.

    Escaped once, Rich renders ``[evidence]`` literally. Escaped twice -- which is what
    this line used to do -- Rich renders ``\\[evidence]``: a backslash the operator never
    typed, in the detail they need in order to fix the problem.
    """

    (workdir / "acme-service").mkdir()

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EEXIST, "cannot create [evidence] directory")

    monkeypatch.setattr(evidence_mod, "scaffold_evidence_files", _raise)
    result = _invoke(["scaffold-evidence", "--target", "acme-service", "--platform", "github"])

    assert result.exit_code == 2, result.output
    flat = _flat(result.output)
    assert "cannot create [evidence] directory" in flat
    assert "\\[evidence]" not in flat, "the detail was escaped twice"


# ======================================================================================
# evaluate: 'Wrote ...' twice, plus the summary footer
# ======================================================================================


def _evaluate_args(target: str, out: str) -> list[str]:
    return [
        "evaluate",
        "--target",
        target,
        "--profile",
        "github-level-1",
        "--output-dir",
        out,
        "--fail-on",
        "none",
        "--quiet",
    ]


def test_evaluate_names_both_reports_under_the_output_dir_as_typed(workdir: Path) -> None:
    """``--output-dir reports`` must be answered ``reports/...``, not the resolved path."""

    _github_repo(workdir)
    result = _invoke(_evaluate_args("acme-service", "reports"))

    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    expected_json = str(Path("reports") / "evaluation-report.json")
    expected_md = str(Path("reports") / "evaluation-report.md")
    assert f"Wrote {expected_json}" in flat
    assert f"Wrote {expected_md}" in flat
    assert _MARKER not in result.output, "the resolved output directory leaked"


def test_evaluate_summary_footer_names_the_output_dir_as_typed(workdir: Path) -> None:
    """The stdout table footer carried the same resolved path."""

    _github_repo(workdir)
    result = _invoke(_evaluate_args("acme-service", "reports"))

    assert result.exit_code == 0, result.output
    assert "Reports: reports" in _flat(result.stdout)
    assert _MARKER not in result.stdout


def test_evaluate_json_mode_reports_written_to_line_is_relative(workdir: Path) -> None:
    """``--format json`` repeats the destination on stderr; it leaked there too."""

    _github_repo(workdir)
    result = _invoke([*_evaluate_args("acme-service", "reports"), "--format", "json"])

    assert result.exit_code == 0, result.output
    assert "Reports written to: reports" in _flat(result.output)
    assert _MARKER not in result.output
    json.loads(result.stdout)  # stdout stays a pure machine contract


def test_evaluate_sarif_line_is_composed_from_the_two_relative_flags(workdir: Path) -> None:
    """``--sarif-output`` is resolved under ``--output-dir``; the echo must not be."""

    _github_repo(workdir)
    result = _invoke([*_evaluate_args("acme-service", "reports"), "--sarif-output", "findings.sarif"])

    assert result.exit_code == 0, result.output
    assert f"Wrote {Path('reports') / 'findings.sarif'}" in _flat(result.output)
    assert _MARKER not in result.output
    assert (workdir / "reports" / "findings.sarif").is_file()


def test_evaluate_scan_evidence_banner_suggests_the_target_as_typed(workdir: Path) -> None:
    """The banner hands the operator a command to run; it must be one that works."""

    _github_repo(workdir)
    result = _invoke([*_evaluate_args("acme-service", "reports"), "--profile", "kubernetes-baseline-1"])

    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    assert 'oss-policy-kit scan-k8s --target "acme-service"' in flat
    assert _MARKER not in result.output


# ======================================================================================
# collect-evidence --dry-run: a preview of paths nobody asked for
# ======================================================================================


def test_collect_evidence_dry_run_preview_stays_relative(workdir: Path) -> None:
    """Target, output directory, and every previewed file, all as the operator typed."""

    _github_repo(workdir)
    result = _invoke(["collect-evidence", "--target", "acme-service", "--platform", "github", "--dry-run"])

    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    evidence_dir = Path("acme-service") / ".oss-policy-kit" / "evidence"
    assert "Target: acme-service" in flat
    assert f"Output dir: {evidence_dir}" in flat
    assert f"+ {evidence_dir / 'branch-protection.json'}" in flat
    assert _MARKER not in result.output, "the resolved preview paths leaked"


def test_collect_evidence_dry_run_honours_a_relative_output_dir(workdir: Path) -> None:
    """An explicit ``--output-dir`` is echoed as typed, not expanded."""

    _github_repo(workdir)
    result = _invoke(
        [
            "collect-evidence",
            "--target",
            "acme-service",
            "--platform",
            "github",
            "--output-dir",
            "collected",
            "--dry-run",
        ]
    )

    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    assert "Output dir: collected" in flat
    assert f"+ {Path('collected') / 'github-rulesets.json'}" in flat
    assert _MARKER not in result.output


# ======================================================================================
# A root option before the subcommand must not be answered with a contradiction
# ======================================================================================


def test_root_target_before_the_subcommand_says_what_is_actually_wrong(workdir: Path) -> None:
    """``--target`` was visibly present, and the error said to supply ``--target``."""

    _github_repo(workdir)
    result = _invoke(["--target", "acme-service", "evaluate", "--profile", "github-level-1"])

    assert result.exit_code == 2, result.output
    flat = _flat(result.output)
    assert "--target was typed before the subcommand" in flat
    assert "oss-policy-kit evaluate --target" in flat, "the message must show the placement that works"
    assert "Provide a repository path as TARGET" not in flat, "the contradictory message survived"


def test_several_misplaced_root_options_are_all_named(workdir: Path) -> None:
    """Naming only the first would send the operator back for a second round."""

    _github_repo(workdir)
    result = _invoke(["--target", "acme-service", "--profile", "github-level-1", "evaluate"])

    assert result.exit_code == 2, result.output
    flat = _flat(result.output)
    assert "--target, --profile were typed before the subcommand" in flat


def test_a_genuinely_missing_target_keeps_the_plain_message(workdir: Path) -> None:
    """Nothing was misplaced, so nothing is invented: the original message stands."""

    result = _invoke(["evaluate", "--profile", "github-level-1"])

    assert result.exit_code == 2, result.output
    flat = _flat(result.output)
    assert "Provide a repository path as TARGET or via --target/-t." in flat
    assert "typed before the subcommand" not in flat


def test_the_compatibility_form_still_honours_the_same_root_options(workdir: Path) -> None:
    """The message points at this form, so it has to keep working."""

    _github_repo(workdir)
    result = _invoke(["--target", "acme-service", "--profile", "github-level-1", "--output-dir", "reports"])

    assert result.exit_code == 0, result.output
    assert (workdir / "reports" / "evaluation-report.json").is_file()


def test_the_documented_placement_after_the_subcommand_still_works(workdir: Path) -> None:
    """The other form the message points at."""

    _github_repo(workdir)
    result = _invoke(_evaluate_args("acme-service", "reports"))

    assert result.exit_code == 0, result.output
    assert (workdir / "reports" / "evaluation-report.json").is_file()
