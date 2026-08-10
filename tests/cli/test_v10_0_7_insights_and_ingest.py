"""v10.0.7 regressions for the Security-Insights / ingest / diff-catalogs group.

Two defect classes, both found by the clean-room validation of the published v10.0.6
wheel.

1. **Exit-3 denial of service on the evaluate gate (critical).** The Security Insights
   reader never applied the documented 200-level nesting budget, so a ~500-level
   ``SECURITY-INSIGHTS.yml`` — one kilobyte, discovered *inside the repository being
   evaluated* rather than typed by the operator — crashed
   ``evaluate --use-insights-evidence`` with ``exit 3: maximum recursion depth
   exceeded``. Evaluating an untrusted clone was therefore a one-file DoS against the
   gate, and the crash threshold was whatever the interpreter's stack happened to be
   (clean at 400 levels, dead at 500). ``ingest-insights`` crashed the same way through
   both ``--target`` discovery and ``--input``. The reader now checks the budget
   explicitly before parsing, like the Scorecard reader, so the verdict is identical on
   every platform.

2. **M-002 path-privacy leaks.** ``ingest-scorecard --input``, ``ingest-insights
   --input`` and ``diff-catalogs --from`` resolved a RELATIVE argument to an absolute
   one purely to print it, leaking the auditor's home directory and OS username;
   ``ingest-scorecard`` also printed an absolute ``File:`` line (and JSON
   ``input_path``) on its success path, and both ingest commands recorded an absolute
   ``searched_root`` in a shareable JSON report.

Every path assertion here uses a RELATIVE argument on purpose: given an absolute one the
user's own string already is the absolute path, so there is nothing the message could
withhold. Asserting on the verbatim echo also dodges the Windows 8.3 short-path trap,
where ``str(tmp_path)`` and its resolved form differ and a "leak" assertion passes for
the wrong reason.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.insights_evidence import (
    load_insights_evidence,
    load_insights_file,
)
from oss_policy_kit.cli.main import app

runner = CliRunner()

#: The budget ``input_limits.MAX_JSON_DEPTH`` documents and this reader must enforce.
_BUDGET = 200


def _clean(text: str) -> str:
    """Collapse whitespace so a Rich line-wrap cannot break a substring assertion."""

    return " ".join(text.split())


def _valid_body() -> str:
    return (
        "header:\n"
        "  schema-version: 1.0.0\n"
        "  last-updated: 2026-06-01T00:00:00Z\n"
        "project-lifecycle:\n"
        "  status: active\n"
        "vulnerability-reporting:\n"
        "  accepts-vulnerability-reports: true\n"
        "  security-policy: https://example.com/SECURITY.md\n"
    )


def _flow_nested(depth: int) -> str:
    """An otherwise-valid Insights document whose ``nested`` value is *depth* levels deep."""

    return _valid_body() + "nested: " + ("{a: " * depth) + "1" + ("}" * depth) + "\n"


def _block_nested(depth: int) -> str:
    """Same, but nested by indentation — no brackets for the depth scanner to count."""

    lines = [_valid_body().rstrip("\n"), "nested:"]
    lines += ["  " * (i + 1) + "a:" for i in range(depth)]
    lines.append("  " * (depth + 1) + "1")
    return "\n".join(lines) + "\n"


def _write_insights(root: Path, text: str) -> Path:
    path = root / "SECURITY-INSIGHTS.yml"
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# 1. the exit-3 denial of service
# --------------------------------------------------------------------------- #


def test_evaluate_with_insights_evidence_survives_a_deep_file(tmp_path: Path) -> None:
    """The critical fence: a hostile Insights file in the *target* cannot crash the gate.

    Before the fix this exited 3 with "Unexpected error: maximum recursion depth
    exceeded" — a one-kilobyte file inside an untrusted clone taking the gate down.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_insights(repo, _flow_nested(500))

    result = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--use-insights-evidence",
            "--output-dir",
            str(tmp_path / "out"),
            "--format",
            "json",
            "--summary-only",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Unexpected error" not in result.output
    assert "Traceback" not in result.output
    assert "recursion" not in result.output.lower()


def test_evaluate_with_insights_evidence_survives_a_deep_block_style_file(tmp_path: Path) -> None:
    """Same fence for indentation-nested YAML, which carries no brackets to count.

    That path is caught by ``RecursionError`` in ``BAD_INPUT_ERRORS`` instead of by the
    depth scanner; both must degrade to "this file contributes no evidence", never crash.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_insights(repo, _block_nested(600))

    result = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(repo),
            "--profile",
            "github-level-1",
            "--use-insights-evidence",
            "--output-dir",
            str(tmp_path / "out"),
            "--format",
            "json",
            "--summary-only",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Unexpected error" not in result.output


@pytest.mark.parametrize("nest", [_flow_nested, _block_nested])
def test_ingest_insights_target_discovery_refuses_deep_file(nest: Callable[[int], str], tmp_path: Path) -> None:
    """``ingest-insights --target`` reports an invalid file (exit 1), never exit 3."""
    _write_insights(tmp_path, nest(500))

    result = runner.invoke(app, ["ingest-insights", "--target", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["found"] is True
    assert payload["valid"] is False
    assert any("nested too deeply" in e for e in payload["validation_errors"]), payload["validation_errors"]
    assert "Unexpected error" not in result.output


def test_ingest_insights_input_flag_refuses_deep_file(tmp_path: Path) -> None:
    """The same guard covers the explicit ``--input`` path."""
    custom = tmp_path / "custom.yml"
    custom.write_text(_flow_nested(500), encoding="utf-8")

    result = runner.invoke(
        app,
        ["ingest-insights", "--target", str(tmp_path), "--input", str(custom), "--format", "json"],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert any("nested too deeply" in e for e in payload["validation_errors"])
    assert "Unexpected error" not in result.output


def test_depth_budget_is_the_documented_200_not_the_interpreter_stack(tmp_path: Path) -> None:
    """Exactly at the budget the file parses; one level past it is refused.

    Pinning both sides is what makes the answer a *documented limit* rather than a
    property of whichever stack the adopter's interpreter happens to have.
    """
    at_budget = tmp_path / "at.yml"
    at_budget.write_text(_flow_nested(_BUDGET), encoding="utf-8")
    doc, error = load_insights_file(at_budget)
    assert error is None
    assert doc is not None

    past_budget = tmp_path / "past.yml"
    past_budget.write_text(_flow_nested(_BUDGET + 1), encoding="utf-8")
    doc, error = load_insights_file(past_budget)
    assert doc is None
    assert error is not None
    assert f"more than {_BUDGET} levels" in error
    # M-002: the refusal names the file, never where it lives.
    assert "past.yml" in error
    assert str(tmp_path) not in error


def test_deep_file_contributes_no_evidence_instead_of_raising(tmp_path: Path) -> None:
    """The engine-side wiring degrades to None; it must not raise into the CLI handler."""
    _write_insights(tmp_path, _flow_nested(500))
    assert load_insights_evidence(tmp_path) is None


def test_unreadable_insights_file_error_has_no_path(tmp_path: Path) -> None:
    """A directory where a file is expected is bad input, and ``str(OSError)`` carries the
    absolute filename — so the message must be built from the shared vocabulary instead.

    The discriminator is a directory name, not ``str(tmp_path)``: ``OSError.__str__``
    renders the filename with ``repr``, which doubles Windows backslashes, so
    ``str(tmp_path) not in error`` silently holds on Windows however badly the message
    leaks. A component name survives that escaping on every platform.
    """
    parent = tmp_path / "SECRET-DIR"
    parent.mkdir()
    as_dir = parent / "SECURITY-INSIGHTS.yml"
    as_dir.mkdir()
    doc, error = load_insights_file(as_dir)
    assert doc is None
    assert error is not None
    assert "SECRET-DIR" not in error
    assert "SECURITY-INSIGHTS.yml" in error


# --------------------------------------------------------------------------- #
# 2. M-002 — a relative argument is echoed, never resolved
# --------------------------------------------------------------------------- #


def test_ingest_insights_missing_input_echoes_typed_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["ingest-insights", "--target", ".", "--input", "nope.yml"])
    assert result.exit_code == 2, result.output
    assert "--input nope.yml is not a file" in _clean(result.output)
    assert str(tmp_path.resolve()) not in result.output


def test_ingest_scorecard_missing_input_echoes_typed_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["ingest-scorecard", "--target", ".", "--input", "nope.json"])
    assert result.exit_code == 2, result.output
    assert "--input nope.json is not a file" in _clean(result.output)
    assert str(tmp_path.resolve()) not in result.output


def test_diff_catalogs_missing_from_echoes_typed_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["diff-catalogs", "--from", "zzz"])
    assert result.exit_code == 2, result.output
    assert "--from zzz does not exist" in _clean(result.output)
    assert str(tmp_path.resolve()) not in result.output


def test_diff_catalogs_catalog_less_dir_echoes_typed_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A directory that exists but holds no catalog is the other half of the same leak."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "snap").mkdir()
    result = runner.invoke(app, ["diff-catalogs", "--from", "snap"])
    assert result.exit_code == 2, result.output
    cleaned = _clean(result.output)
    assert "--from snap" in cleaned
    assert "controls/catalog.yaml" in cleaned
    assert str(tmp_path.resolve()) not in result.output


def test_diff_catalogs_missing_to_echoes_typed_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    kit = tmp_path / "kit" / "controls"
    kit.mkdir(parents=True)
    (kit / "catalog.yaml").write_text("controls:\n  - id: A\n    title: Control A\n", encoding="utf-8")
    result = runner.invoke(app, ["diff-catalogs", "--from", "kit", "--to", "zzz"])
    assert result.exit_code == 2, result.output
    assert "--to zzz does not exist" in _clean(result.output)
    assert str(tmp_path.resolve()) not in result.output


# --------------------------------------------------------------------------- #
# 2b. M-002 — the success path and the shareable JSON report
# --------------------------------------------------------------------------- #

_SCORECARD_RESULT = {
    "date": "2026-06-01T00:00:00Z",
    "score": 7.3,
    "checks": [{"name": "Token-Permissions", "score": 9, "reason": "read-only"}],
}


def _seed_scorecard(root: Path, rel: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_SCORECARD_RESULT), encoding="utf-8")
    return path


def test_ingest_scorecard_success_file_line_is_not_absolute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The discovered result is cited relative to ``--target``, never as an absolute path."""
    monkeypatch.chdir(tmp_path)
    rel = ".oss-policy-kit/evidence/scorecard-result.json"
    _seed_scorecard(tmp_path, rel)

    result = runner.invoke(app, ["ingest-scorecard", "--target", "."])
    assert result.exit_code == 0, result.output
    assert f"File: {rel}" in _clean(result.stdout)
    assert str(tmp_path.resolve()) not in result.stdout


def test_ingest_scorecard_json_report_input_path_is_relative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The JSON report is shareable evidence, so it carries no absolute path either."""
    monkeypatch.chdir(tmp_path)
    rel = ".oss-policy-kit/evidence/scorecard-result.json"
    _seed_scorecard(tmp_path, rel)

    result = runner.invoke(app, ["ingest-scorecard", "--target", ".", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["input_path"] == rel


def test_ingest_scorecard_explicit_relative_input_is_echoed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _seed_scorecard(tmp_path, "ev/sc.json")

    result = runner.invoke(app, ["ingest-scorecard", "--target", ".", "--input", "ev/sc.json", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["input_path"] == "ev/sc.json"


def test_ingest_scorecard_unparseable_file_line_is_not_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    rel = ".oss-policy-kit/evidence/scorecard-result.json"
    seeded = _seed_scorecard(tmp_path, rel)
    seeded.write_text("{ not json", encoding="utf-8")

    result = runner.invoke(app, ["ingest-scorecard", "--target", ".", "--format", "json"])
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["input_path"] == rel
    assert str(tmp_path.resolve()) not in result.stdout


@pytest.mark.parametrize("cmd", ["ingest-insights", "ingest-scorecard"])
def test_not_found_report_searched_root_echoes_typed_target(
    cmd: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``searched_root`` recorded the resolved ``--target``; it now echoes what was typed."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, [cmd, "--target", ".", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["searched_root"] == "."
    assert str(tmp_path.resolve()) not in result.stdout
