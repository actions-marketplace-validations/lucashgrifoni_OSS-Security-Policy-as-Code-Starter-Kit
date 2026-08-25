"""Rich must not delete part of a RESULT the operator has to act on.

v10.0.6 escaped the ERROR messages. Result rendering was left raw, so the same silent
deletion survived exactly where it costs the most. A control that fails because of a
workflow literally named ``[bold]unsafe.yml`` printed

    pull_request_target detected in: unsafe.yml

in the console table, while ``evaluation-report.json`` carried the real name all along.
The operator goes looking for a file that does not exist, and nothing in the run reports
a problem: the text is right in the evaluator, right in the artifact, and wrong only
after Rich renders it.

Three surfaces are covered, and all three share the property "the console is the only
place this is wrong":

* the ``evaluate`` results table -- ``cli/terminal_ui.render_eval_results_table``
* the ``--verbose`` per-control lines -- ``application/engine._evaluate_control``
* the ``evaluate-many`` progress stream -- ``cli/batch.evaluate_many_cmd``

Every test pairs two assertions on purpose:

* the HONESTY assertion, that the same fragment rendered WITHOUT the escape really does
  lose its bracketed run. Rich only consumes a bracketed run that could plausibly be a
  style name, so a fixture like ``[CI-PIN-008]`` prints literally and would prove
  nothing. This assertion is what keeps the fixtures real.
* the REQUIREMENT assertion, that the fragment survives the production path verbatim AND
  that no backslash precedes it. ``"[bold]x" in rendered`` is satisfied by a
  double-escaped ``\\[bold]x`` as well, so the backslash has to be excluded explicitly --
  showing the operator an escape character they never typed is its own defect.

The over-escape direction is covered too: the ``[red]`` / ``[dim]`` tags in these strings
are OURS, and escaping the whole f-string instead of the interpolated value would print
them on screen.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from rich.console import Console
from tests.conftest import ROOT

from oss_policy_kit.application import engine
from oss_policy_kit.application.evaluators import EvalContext
from oss_policy_kit.application.loader import ApplicabilitySpec, ControlSpec, ProfileSpec
from oss_policy_kit.cli import terminal_ui as tui
from oss_policy_kit.domain.models import ControlResult, ControlStatus, EvalOutcome, ExecutionReport
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

#: A workflow file name that collides with a real Rich style. This is the shipped shape of
#: the defect: the fragment names the very file the operator has to open.
HOSTILE = "[bold]unsafe.yml"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _plain(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _render(renderable: object) -> str:
    """Render through a Rich console configured the way the CLI configures its own."""

    buf = io.StringIO()
    Console(file=buf, width=200, no_color=True, highlight=False, legacy_windows=False).print(renderable)
    return _plain(buf.getvalue())


def _collapse(text: str) -> str:
    """Flatten Rich's soft wrapping so a fragment can be matched regardless of layout."""

    return " ".join(text.split())


def _assert_rich_would_eat_it(fragment: str) -> None:
    """Fixture honesty: prove the fragment is one Rich actually deletes when unescaped."""

    assert fragment not in _render(f"detected in: {fragment}"), (
        f"fixture {fragment!r} does not exercise Rich markup; it renders literally, so the "
        "test below would pass with the fix reverted"
    )


def _assert_survives(rendered: str, fragment: str) -> None:
    assert fragment in rendered, f"Rich deleted part of {fragment!r} from:\n{rendered}"
    assert "\\" + fragment not in rendered, (
        f"{fragment!r} was escaped twice; the operator sees a backslash they never typed:\n{rendered}"
    )


# --------------------------------------------------------------------------- #
# evaluate results table -- cli/terminal_ui.render_eval_results_table
# --------------------------------------------------------------------------- #


def _result(
    *,
    control_id: str = "CI-PIN-008",
    confidence: str = "medium",
    reason: str = "Mutable refs detected.",
    status: ControlStatus = ControlStatus.FAIL,
) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        title="Third-party actions pinned",
        category="supply_chain",
        status=status,
        profile="github-level-1",
        evidence_sources=[],
        confidence=confidence,
        reason=reason,
        remediation="Pin SHAs.",
    )


def _report(
    *,
    profile_id: str = "github-level-1",
    target_path: str = "repos/repo-a",
    results: list[ControlResult] | None = None,
) -> ExecutionReport:
    rows = [_result()] if results is None else results
    return ExecutionReport(
        schema_version="reports/2.0",
        generated_at="2026-06-15T12:00:00Z",
        kit_version="test",
        target_path=target_path,
        profile_id=profile_id,
        profile_title="GitHub Level 1",
        summary_by_status={r.status.value: 1 for r in rows},
        results=rows,
        operational_warnings=[],
    )


def test_results_table_reason_cell_keeps_the_workflow_name_it_names() -> None:
    """The shipped defect: the Reason cell sent the operator to a file that is not there."""

    _assert_rich_would_eat_it(HOSTILE)
    reason = f"pull_request_target detected in: {HOSTILE}"

    table = tui.render_eval_results_table(_report(results=[_result(reason=reason)]), unicode_icons=False)

    _assert_survives(_collapse(_render(table)), HOSTILE)


def test_results_table_id_cell_keeps_its_brackets() -> None:
    """Every FREE-FORM ``str`` cell is markup to Rich, not only the one that carried the defect.

    ``confidence`` was asserted here beside the id, and is not free form any more: an
    evaluator's word is settled into the four-value enum by ``ControlResult``, so
    ``[dim]low`` reaches the table as ``low``. That is deliberate -- the JSON and the SARIF
    had always normalized it while this table printed the raw string, so one run produced
    artifacts that disagreed about the same field.

    The escaping is unchanged; the field simply cannot carry markup any more, and that is
    asserted below rather than quietly dropped.
    """

    hostile_id = "[bold]CI-1"
    _assert_rich_would_eat_it(hostile_id)

    table = tui.render_eval_results_table(
        _report(results=[_result(control_id=hostile_id, confidence="[dim]low")]),
        unicode_icons=False,
    )
    out = _collapse(_render(table))

    _assert_survives(out, hostile_id)
    assert "[dim]" not in out, "a confidence carrying markup reached the table unnormalized"
    assert "low" in out, "the normalized confidence is not shown at all"


def test_results_table_title_keeps_the_profile_id_and_the_target_name() -> None:
    """The title names what was evaluated; it may not lose half of either value."""

    hostile_profile = "[bold]prof-x"
    hostile_target = "[bold]weird-repo"
    _assert_rich_would_eat_it(hostile_profile)
    _assert_rich_would_eat_it(hostile_target)

    table = tui.render_eval_results_table(
        _report(profile_id=hostile_profile, target_path=f"repos/{hostile_target}"),
        unicode_icons=False,
    )
    out = _collapse(_render(table))

    _assert_survives(out, hostile_profile)
    _assert_survives(out, hostile_target)


def test_results_table_status_cell_is_still_styled_not_escaped() -> None:
    """Over-escape guard: the colour tags around the status are ours and must stay tags."""

    out = _render(tui.render_eval_results_table(_report(), unicode_icons=False))

    assert "fail" in out
    assert "[red]" not in out
    assert "[/red]" not in out


# --------------------------------------------------------------------------- #
# --verbose per-control lines -- application/engine._evaluate_control
# --------------------------------------------------------------------------- #


def _ctx(repo_root: Path, emit: object) -> EvalContext:
    return EvalContext(
        repo_root=repo_root,
        profile_id="p-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        verbose_emit=emit,  # type: ignore[arg-type]
    )


def _outcome(reason: str) -> EvalOutcome:
    return EvalOutcome(
        status=ControlStatus.FAIL,
        reason=reason,
        remediation="Pin SHAs.",
        evidence_sources=[],
        confidence="medium",
    )


def _run_control(
    monkeypatch: pytest.MonkeyPatch,
    repo_root: Path,
    *,
    cid: str = "X-1",
    title: str = "Third-party actions pinned",
    reason: str = "Mutable refs detected.",
    applicability: ApplicabilitySpec | None = None,
    applicability_engine: bool = False,
) -> str:
    """Drive one control and return its ``--verbose`` lines as the operator sees them."""

    monkeypatch.setitem(engine.EVALUATOR_REGISTRY, cid, lambda _c: _outcome(reason))
    spec = ControlSpec(id=cid, title=title, category="supply_chain", automation="static", applicability=applicability)
    profile = ProfileSpec(id="p-1", title="P", description="d", audience="maintainers", control_ids=(cid,))
    lines: list[str] = []
    engine._evaluate_control(
        cid,
        _ctx(repo_root, lines.append),
        profile,
        {cid: spec},
        {},
        [],
        applicability_engine=applicability_engine,
    )
    assert lines, "no --verbose line was emitted"
    return _collapse("\n".join(_render(line) for line in lines))


def test_verbose_result_line_keeps_the_workflow_name_it_names(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _assert_rich_would_eat_it(HOSTILE)

    out = _run_control(monkeypatch, tmp_path, reason=f"pull_request_target detected in: {HOSTILE}")

    assert "Result:" in out
    _assert_survives(out, HOSTILE)


def test_verbose_control_line_keeps_a_bracketed_control_id_and_title(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A custom ``--kit-root`` catalog supplies both of these; neither is ours to trust."""

    hostile_id = "[bold]X-1"
    _assert_rich_would_eat_it(hostile_id)

    out = _run_control(monkeypatch, tmp_path, cid=hostile_id, title=f"Pin {HOSTILE}")

    _assert_survives(out, hostile_id)
    _assert_survives(out, HOSTILE)


def test_verbose_not_applicable_line_keeps_a_bracketed_control_id_and_title(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The applicability short-circuit prints its own line and had the same hole."""

    hostile_id = "[bold]X-1"
    _assert_rich_would_eat_it(hostile_id)

    out = _run_control(
        monkeypatch,
        tmp_path,
        cid=hostile_id,
        title=f"Pin {HOSTILE}",
        applicability=ApplicabilitySpec(requires_any_files=("no-such-file-*.txt",)),
        applicability_engine=True,
    )

    assert "not applicable" in out
    _assert_survives(out, hostile_id)
    _assert_survives(out, HOSTILE)


def test_verbose_line_keeps_its_dim_styling_rather_than_printing_the_tag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Over-escape guard: ``[dim]`` is our style, so it must never reach the screen."""

    out = _run_control(monkeypatch, tmp_path)

    assert "Result:" in out
    assert "[dim]" not in out
    assert "[/dim]" not in out


# --------------------------------------------------------------------------- #
# evaluate-many progress stream -- cli/batch.evaluate_many_cmd
# --------------------------------------------------------------------------- #


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("PYTHONHOME", "PYTHONSTARTUP", "PYTHONBREAKPOINT", "PYTHONINSPECT", "PYTHONEXECUTABLE"):
        env.pop(key, None)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "160"
    env["LINES"] = "40"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def test_evaluate_many_progress_line_keeps_a_bracketed_directory_name(tmp_path: Path) -> None:
    """The progress stream is the only place a long batch is watched while it runs.

    Run as a subprocess so stdout and stderr stay separate (``CliRunner`` merges them) and
    so the assertion sees exactly what a piped console receives.
    """

    _assert_rich_would_eat_it("[bold]repo-a")

    root = tmp_path / "roots"
    child = root / "[bold]repo-a"
    (child / ".github" / "workflows").mkdir(parents=True)
    (child / ".github" / "workflows" / "ci.yml").write_text("name: ci\non: [push]\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "oss_policy_kit",
            "evaluate-many",
            "--target-root",
            str(root),
            "--profiles",
            "github-level-1",
            "--output-dir",
            str(out_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_subprocess_env(),
        stdin=subprocess.DEVNULL,
        timeout=300,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr

    # The consolidated artifact was never wrong; the console was. Assert both, so a future
    # "fix" cannot satisfy this test by mangling the JSON to match a broken console.
    batch = json.loads((out_dir / "evaluation-batch.json").read_text(encoding="utf-8"))
    assert "[bold]repo-a" in json.dumps(batch)

    progress = [ln for ln in _plain(proc.stderr).splitlines() if "[1/1]" in ln]
    assert progress, f"no progress line on stderr:\n{proc.stderr}"
    _assert_survives(_collapse(" ".join(progress)), "[bold]repo-a")
