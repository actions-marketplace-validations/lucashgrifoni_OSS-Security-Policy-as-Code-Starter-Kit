"""v10.0.7 hotfix regressions for ``export-evidence`` (clean-room lane: export-evidence).

Two confirmed defects, each with at least one test that fails before the fix:

- **A perfect repository became 14 alerts.** ``--format sarif`` emitted every control
  as a SARIF result at ``level: note`` with no ``kind``. A SARIF result *is* a finding
  to its consumer -- SARIF 2.1.0 3.27.9 defaults ``result.kind`` to ``"fail"``, and
  GitHub code scanning does not implement ``kind`` at all -- so a 14/14 PASS repository
  uploaded 14 alerts reading "SECURITY.md present.", and a NOT_APPLICABLE control was
  indistinguishable from a failing one. Findings only are emitted now (the filter
  ``evaluate --sarif-output`` already applies); the evaluated control set stays visible
  in ``tool.driver.rules`` and the omission is counted in the run's ``properties``.

- **exit 3 on a hostile report.** ``--report`` crashed with the exit-3 "unexpected
  internal error" on a 3000-level nested document and on a 5000-digit integer literal,
  on all six formats -- the latter handing the user CPython's own
  ``sys.set_int_max_str_digits()`` advice. Both are ordinary bad input: exit 2, in the
  kit's shared error vocabulary, naming the basename only (M-002).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import export_evidence as ee
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import InvalidInputError

runner = CliRunner()

_FORMATS = ("chainloop", "sarif", "spdx", "oscal", "in-toto-bundle", "gemara")

_SCHEMA = "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/reports/2.0"


def _flat(text: str) -> str:
    """Collapse Rich's wrapping so a substring assertion is not width-dependent."""
    return " ".join(text.split())


def _report(controls: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": _SCHEMA,
        "contract_version": "reports/2.0",
        "target_path": "examples/hardened-repo",
        "profile": {"id": "github-level-1"},
        "summary_by_status": {"PASS": len(controls)},
        "controls": controls,
    }


def _perfect_report(n: int = 14) -> dict[str, object]:
    """A repository where every control holds -- the report that produced 14 alerts."""
    return _report(
        [{"id": f"GOV-SEC-{i:03d}", "state": "PASS", "message": "SECURITY.md present."} for i in range(1, n + 1)]
    )


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _export(target: Path, fmt: str, *, report: Path, out: Path, validate: bool = False):  # noqa: ANN202
    argv = ["export-evidence", "--target", str(target), "--format", fmt, "--report", str(report), "--output", str(out)]
    if validate:
        argv.append("--validate")
    return runner.invoke(app, argv)


# --- Defect 1: a passing control is not a SARIF finding ----------------------


def test_perfect_report_emits_no_sarif_results() -> None:
    """14/14 PASS -> zero results. Fails before the fix (14 note-level results)."""
    doc = ee._render_sarif(_perfect_report())
    run = doc["runs"][0]
    assert run["results"] == []
    # ...but the kit still says which controls it checked: nothing is silently lost.
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [f"GOV-SEC-{i:03d}" for i in range(1, 15)]
    assert run["properties"]["kit_non_finding_controls_omitted"] == 14
    assert run["properties"]["kit_non_finding_states"] == {"PASS": 14}
    assert ee._validate(doc, "sarif") == []


@pytest.mark.parametrize(
    ("control", "expected"),
    [
        ({"id": "C", "state": "PASS"}, None),
        ({"id": "C", "state": "ATTESTED"}, None),
        ({"id": "C", "state": "SELF_ATTESTED"}, None),
        ({"id": "C", "state": "NOT_APPLICABLE"}, None),
        ({"id": "C", "state": "not-applicable"}, None),  # hyphen/lower-case variant
        ({"id": "C", "state": "UNKNOWN", "reason": "waived"}, None),
        ({"id": "C", "state": "UNKNOWN", "reason": "skipped-by-flag"}, None),
        ({"id": "C", "state": "FAIL"}, "error"),
        ({"id": "C", "state": "UNKNOWN", "reason": "manual-review-required"}, "warning"),
        ({"id": "C", "state": "UNKNOWN", "reason": "evaluator-error"}, "warning"),
        ({"id": "C", "state": "UNKNOWN"}, "warning"),  # unqualified: still needs a human
        ({"id": "C", "state": "MANUAL_REVIEW_REQUIRED"}, "warning"),
        ({"id": "C", "state": "SOMETHING-NEW"}, "warning"),  # unknown state stays visible
    ],
)
def test_state_decides_whether_a_control_is_a_finding(control: dict[str, object], expected: str | None) -> None:
    assert ee._sarif_result_level(control) == expected


def test_only_findings_reach_results_and_they_declare_kind_fail() -> None:
    """A mixed report: the two findings survive, the four non-findings do not."""
    doc = ee._render_sarif(
        _report(
            [
                {"id": "GOV-SEC-001", "state": "PASS", "message": "SECURITY.md present."},
                {"id": "X-NA-001", "state": "NOT_APPLICABLE", "message": "no packages published."},
                {"id": "W-WAIVED-1", "state": "UNKNOWN", "reason": "waived", "message": "accepted risk."},
                {"id": "S-SKIP-1", "state": "UNKNOWN", "reason": "skipped-by-flag", "message": "skipped."},
                {"id": "CI-PIN-008", "state": "FAIL", "message": "actions pinned to mutable refs"},
                {"id": "GH-PROV-023", "state": "UNKNOWN", "reason": "manual-review-required", "message": "no ev."},
            ]
        )
    )
    run = doc["runs"][0]
    assert {r["ruleId"]: r["level"] for r in run["results"]} == {"CI-PIN-008": "error", "GH-PROV-023": "warning"}
    # every emitted result is explicitly a finding
    assert all(r["kind"] == "fail" for r in run["results"])
    # messages still ride along (they are what the alert says)
    assert {r["message"]["text"] for r in run["results"]} == {"actions pinned to mutable refs", "no ev."}
    # the four non-findings are accounted for, not silently dropped
    assert run["properties"]["kit_non_finding_states"] == {"NOT_APPLICABLE": 1, "PASS": 1, "UNKNOWN": 2}
    assert len(run["tool"]["driver"]["rules"]) == 6
    assert ee._validate(doc, "sarif") == []


def test_sarif_census_is_ordered_independently_of_the_report() -> None:
    """The census key order must come from the census, not from the order the controls
    happen to appear in -- two reports with the same verdicts must export identically
    (v10.0.2 reproducibility class). The controls below are deliberately NOT in sorted
    state order."""
    doc = ee._render_sarif(
        _report(
            [
                {"id": "A-PASS", "state": "PASS"},
                {"id": "B-WAIVED", "state": "UNKNOWN", "reason": "waived"},
                {"id": "C-NA", "state": "NOT_APPLICABLE"},
            ]
        )
    )
    census = doc["runs"][0]["properties"]["kit_non_finding_states"]
    assert list(census) == ["NOT_APPLICABLE", "PASS", "UNKNOWN"] == sorted(census)


def test_sarif_render_is_byte_identical_across_runs() -> None:
    """The new run properties must not reintroduce non-determinism (v10.0.2 class).

    Serialized the way the command actually writes the file (``indent=2``, no key
    sorting), so a difference in emitted order is a difference in the artifact.

    Two renders of the *same* report must agree byte for byte. That is what catches a
    ``uuid4`` or a wall-clock read creeping back into the renderer -- the exact class
    v10.0.2 fixed by routing every timestamp through ``SOURCE_DATE_EPOCH`` and swapping
    ``uuid4`` for ``uuid5`` over stable content.

    A second render of a *separately built* report is asserted too. The first pair alone
    would pass if the renderer cached its output on the report object; rendering a
    freshly built but equal report proves the determinism is in the rendering, not in a
    memo.
    """
    report = _perfect_report(3)
    first = json.dumps(ee._render_sarif(report), indent=2)
    second = json.dumps(ee._render_sarif(report), indent=2)
    assert first == second, "two renders of one report disagree; the renderer is not deterministic"

    rebuilt = json.dumps(ee._render_sarif(_perfect_report(3)), indent=2)
    assert first == rebuilt, (
        "an equal report rendered from scratch produced different bytes, so the output "
        "depends on something outside the report -- a clock, a uuid, or shared state"
    )


def test_cli_perfect_report_writes_alert_free_sarif_and_validates(tmp_path: Path) -> None:
    """End to end: exit 0, --validate still passes, and the artifact carries no alert."""
    rep = tmp_path / "evaluation-report.json"
    _write(rep, _perfect_report())
    out = tmp_path / "ev.sarif.json"
    res = _export(tmp_path, "sarif", report=rep, out=out, validate=True)
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"] == []


def test_cli_failing_control_is_still_reported(tmp_path: Path) -> None:
    """Guard against over-correction: omitting non-findings must not silence findings."""
    rep = tmp_path / "evaluation-report.json"
    _write(rep, _report([{"id": "CI-PIN-008", "state": "FAIL", "message": "actions pinned to mutable refs"}]))
    out = tmp_path / "ev.sarif.json"
    res = _export(tmp_path, "sarif", report=rep, out=out, validate=True)
    assert res.exit_code == 0, res.output
    results = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert [(r["ruleId"], r["level"], r["kind"]) for r in results] == [("CI-PIN-008", "error", "fail")]


# --- Defect 2: a hostile report is exit 2, never exit 3 ----------------------


def _deep_report(path: Path, depth: int = 3000) -> Path:
    """A document nested past the parser's stack (and past MAX_JSON_DEPTH)."""
    path.write_text('{"controls":' + "[" * depth + "]" * depth + "}", encoding="utf-8")
    return path


def _bigint_report(path: Path, digits: int = 5000) -> Path:
    """A document with an integer literal past CPython's 4300-digit conversion limit."""
    path.write_text('{"controls":[],"n":' + "9" * digits + "}", encoding="utf-8")
    return path


def test_deeply_nested_report_is_rejected_not_crashed(tmp_path: Path) -> None:
    """Unit: exit-2 error, shared wording, and no path component at all (M-002)."""
    rep = _deep_report(tmp_path / "deep.json")
    with pytest.raises(InvalidInputError) as ei:
        ee._read_report(rep)
    msg = ei.value.message
    assert "deep.json" in msg
    # The explicit budget, not an incidental RecursionError: the C JSON scanner raises
    # at ~3000 levels on Windows' 1 MB stack and parses the same document on Linux' 8 MB
    # one, so asserting only "nested too deeply" would pass here and protect nobody on CI.
    assert "nested too deeply" in msg and "more than 200 levels" in msg, msg
    # No directory separator can appear: the message is built from the basename only,
    # so this fails for any variant that resolves or echoes the path.
    assert "/" not in msg and "\\" not in msg, msg


def test_nesting_budget_refuses_what_the_parser_would_accept(tmp_path: Path) -> None:
    """The platform-independent half of the guard.

    300 levels is past the kit's 200-level budget but far inside every platform's
    parser stack: ``json.loads`` accepts this document everywhere. Only the explicit
    pre-parse budget refuses it, so this test fails on every platform if the guard is
    removed -- unlike a 3000-level document, which Windows happens to refuse anyway.
    """
    raw = '{"controls":' + "[" * 300 + "]" * 300 + "}"
    assert json.loads(raw)  # the parser itself has no objection
    rep = tmp_path / "deep-300.json"
    rep.write_text(raw, encoding="utf-8")
    with pytest.raises(InvalidInputError, match="more than 200 levels"):
        ee._read_report(rep)


def test_bigint_report_is_rejected_without_cpython_advice(tmp_path: Path) -> None:
    """Unit: the message names the file's problem, not the interpreter's knob."""
    rep = _bigint_report(tmp_path / "big.json")
    with pytest.raises(InvalidInputError) as ei:
        ee._read_report(rep)
    msg = ei.value.message
    assert "big.json" in msg
    # Same sentence `evaluate --scorecard-json` produces for the same input.
    assert "4300 digits" in msg
    assert "set_int_max_str_digits" not in msg, msg
    assert "/" not in msg and "\\" not in msg, msg


@pytest.mark.parametrize("fmt", _FORMATS)
@pytest.mark.parametrize("kind", ("deep", "bigint"))
def test_hostile_report_exits_2_on_every_format(tmp_path: Path, fmt: str, kind: str) -> None:
    """All six formats: exit 2, no traceback, no evidence file, no absolute path."""
    rep = tmp_path / f"{kind}.json"
    _deep_report(rep) if kind == "deep" else _bigint_report(rep)
    out = tmp_path / f"ev-{fmt}.json"
    res = _export(tmp_path, fmt, report=rep, out=out)
    flat = _flat(res.output)
    assert res.exit_code == 2, f"{fmt}/{kind} -> {res.exit_code}\n{res.output}"
    assert "Unexpected error" not in flat, f"{fmt}/{kind} took the exit-3 branch\n{res.output}"
    assert f"{kind}.json" in flat, res.output
    assert str(tmp_path) not in flat, f"{fmt}/{kind} leaked an absolute path\n{res.output}"
    assert not out.exists(), f"{fmt}/{kind} wrote evidence for an unreadable report"


def test_hostile_report_via_auto_discovery_also_exits_2(tmp_path: Path) -> None:
    """The guard sits in the reader, so the auto-discovered report is covered too."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    _bigint_report(out_dir / "evaluation-report.json")
    res = runner.invoke(
        app,
        ["export-evidence", "--target", str(tmp_path), "--format", "sarif", "--output", str(tmp_path / "ev.json")],
    )
    assert res.exit_code == 2, res.output
    assert "Unexpected error" not in _flat(res.output)


def test_an_honest_report_is_still_accepted(tmp_path: Path) -> None:
    """The depth guard must refuse hostile nesting, not ordinary reports."""
    rep = tmp_path / "evaluation-report.json"
    _write(rep, _perfect_report(2))
    assert ee._read_report(rep)["target_path"] == "examples/hardened-repo"
