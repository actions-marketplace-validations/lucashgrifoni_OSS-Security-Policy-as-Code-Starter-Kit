"""ADR-028 PR1: the ATTESTED domain state is wired end-to-end.

Proves that ``ControlStatus.ATTESTED`` scores as passing on its own summary line,
maps to a gate role, is accepted by the reports/2.0 JSON schema (the only contract
since v9.0.0, ADR-043), maps to the reports/2.0 ``ATTESTED`` state, and renders —
with zero score inflation (decision D2).
"""

from __future__ import annotations

import json

from tests.conftest import EXAMPLE_HARDENED, ROOT
from typer.testing import CliRunner

from oss_policy_kit.application import engine
from oss_policy_kit.application.evidence_projection import gate_role_for
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.models import ControlResult, ControlStatus, ExecutionReport

runner = CliRunner()


def _result(control_id: str, status: ControlStatus, *, weight: int = 1) -> ControlResult:
    return ControlResult(
        control_id=control_id,
        title=control_id,
        category="SA",
        status=status,
        profile="test-profile",
        evidence_sources=[],
        confidence="high",
        reason="",
        remediation="",
        weight=weight,
    )


# --------------------------------------------------------------------------- #
# enum + scoring
# --------------------------------------------------------------------------- #


def test_attested_is_a_distinct_passing_state() -> None:
    assert ControlStatus.ATTESTED.value == "attested"
    assert ControlStatus.ATTESTED is not ControlStatus.SELF_ATTESTED
    assert ControlStatus.ATTESTED in engine._PASSING_STATUSES


def test_attested_counts_as_passing_in_weighted_score() -> None:
    results = [
        _result("A", ControlStatus.PASS, weight=2),
        _result("B", ControlStatus.ATTESTED, weight=3),
        _result("C", ControlStatus.FAIL, weight=1),
    ]
    score = engine._compute_weighted_score(results)
    assert score.earned == 5  # pass(2) + attested(3)
    assert score.possible == 6  # + fail(1)
    assert score.percent == round(5 / 6 * 100, 1)


def test_attested_gets_its_own_summary_line() -> None:
    summary = engine._summarize([_result("A", ControlStatus.PASS), _result("B", ControlStatus.ATTESTED)])
    assert summary["attested"] == 1
    assert summary["pass"] == 1  # not merged into pass


# --------------------------------------------------------------------------- #
# gate role + reports/2.0 mapping
# --------------------------------------------------------------------------- #


def test_attested_gate_role_is_passed_observation() -> None:
    assert gate_role_for(ControlStatus.ATTESTED) == "passed_observation"


def test_attested_maps_to_reports_v2_state() -> None:
    assert engine.map_status_to_reports_v2("attested") == ("ATTESTED", None)


# --------------------------------------------------------------------------- #
# schema + rendering
# --------------------------------------------------------------------------- #


_REPORTS_2_0_SCHEMA_PATH = ROOT / "src" / "oss_policy_kit" / "data" / "schema" / "reports" / "2.0.json"


def test_reports_2_0_schema_accepts_attested_and_self_attested() -> None:
    """The reports/2.0 state enum carries both attestation-derived states (v9.0.3).

    ATTESTED (ADR-028, verified attestation) and SELF_ATTESTED (ADR-033,
    self-reported evidence) must both be valid control states AND valid
    summary_by_status keys — real azure/aws evidence-backed reports emit
    SELF_ATTESTED, so the published schema has to accept it.
    """
    schema = json.loads(_REPORTS_2_0_SCHEMA_PATH.read_text(encoding="utf-8"))
    state_enum = schema["properties"]["controls"]["items"]["properties"]["state"]["enum"]
    assert "ATTESTED" in state_enum
    assert "SELF_ATTESTED" in state_enum
    summary_pattern = next(iter(schema["properties"]["summary_by_status"]["patternProperties"]))
    assert "ATTESTED" in summary_pattern
    assert "SELF_ATTESTED" in summary_pattern


def test_status_maps_agree_between_engine_and_reporting() -> None:
    """engine.REPORTS_V2_STATUS_MAP and reporting.REPORTS_V2_STATUS_MAP must not drift.

    v9.0.3 regression: the engine copy was missing 'waived' (a waived control mapped
    to the generic 'unmapped-source-status' reason instead of 'waived').
    """
    from oss_policy_kit.application import reporting

    assert engine.REPORTS_V2_STATUS_MAP == reporting.REPORTS_V2_STATUS_MAP
    assert engine.map_status_to_reports_v2("waived") == ("UNKNOWN", "waived")
    assert engine.map_status_to_reports_v2("self-attested") == ("SELF_ATTESTED", None)


def test_attested_control_renders_without_crash() -> None:
    report = ExecutionReport(
        schema_version="reports/2.0",
        generated_at="2026-06-08T00:00:00Z",
        kit_version="test",
        target_path="/tmp/repo",
        profile_id="test-profile",
        profile_title="Test",
        summary_by_status={"attested": 1},
        results=[_result("PROV-VERIFY-061", ControlStatus.ATTESTED)],
        operational_warnings=[],
    )
    table = terminal_ui.render_eval_results_table(report, unicode_icons=True)
    console = terminal_ui.build_console()
    with console.capture() as cap:
        console.print(table)
    assert "attested" in cap.get()


# --------------------------------------------------------------------------- #
# guard: no bundled evaluator emits ATTESTED yet (outputs unchanged / no inflation)
# --------------------------------------------------------------------------- #


def test_no_bundled_evaluator_emits_attested(tmp_path) -> None:
    res = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-level-1",
            "--format",
            "json",
            "--summary-only",
            "--output-dir",
            str(tmp_path / "o"),
        ],
    )
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    summary = payload.get("summary_by_status", {})
    assert "attested" not in summary
