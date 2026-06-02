"""ADR-033: opt-in Security Insights -> self-attested control evidence wiring.

Covers the assurance fence by construction:

- the disclosure allowlist (GOV-DISC-013, CRA-ART14-COORD-002, GOV-DISC-065) is
  lifted from ``manual-review-required`` to ``SELF_ATTESTED`` ONLY when the target
  declares a vulnerability-reporting channel in SECURITY-INSIGHTS.yml AND only when
  the evidence is supplied (the ``--use-insights-evidence`` flag is modeled by
  passing ``insights_evidence`` into ``EvalContext``);
- a self-report NEVER lifts a deterministic FAIL;
- reports/2.0 surfaces the new status as ``SELF_ATTESTED`` (distinct from PASS/UNKNOWN).
"""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.engine import map_status_to_reports_v2
from oss_policy_kit.application.evaluators import (
    EvalContext,
    eval_cra_art14_coord_002,
    eval_gov_disc_013,
    eval_gov_disc_065,
)
from oss_policy_kit.application.insights_evidence import InsightsEvidence, load_insights_evidence
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

# A generic SECURITY.md: present and non-placeholder (so GOV-DISC-013 is not FAIL),
# but with no private-reporting channel, disclosure phrase, or SLA keyword (so all
# three allowlisted controls return manual-review-required from clone-only signals).
_GENERIC_SECURITY_MD = "# Security\n\nWe maintain this project with care and act on issues we become aware of.\n"

_INSIGHTS_WITH_CHANNEL = """\
header:
  schema-version: "1.0.0"
  last-updated: "2026-06-02"
project-lifecycle:
  status: active
vulnerability-reporting:
  accepts-vulnerability-reports: true
  security-policy: "https://example.com/security"
  email-contact: "security@example.com"
"""


def _ctx(tmp_path: Path, *, insights_evidence: InsightsEvidence | None = None) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
        insights_evidence=insights_evidence,
    )


def _channel_evidence() -> InsightsEvidence:
    return InsightsEvidence(
        source_rel="SECURITY-INSIGHTS.yml",
        valid=True,
        signals={
            "accepts_vulnerability_reports": True,
            "security_policy_url": "https://example.com/security",
            "security_contacts": ["security@example.com"],
        },
    )


# --- Predicate -------------------------------------------------------------


def test_predicate_true_when_valid_and_channel() -> None:
    assert _channel_evidence().declares_vulnerability_reporting_channel() is True


def test_predicate_false_when_invalid() -> None:
    ev = _channel_evidence()
    invalid = InsightsEvidence(source_rel=ev.source_rel, valid=False, signals=ev.signals)
    assert invalid.declares_vulnerability_reporting_channel() is False


def test_predicate_false_without_channel() -> None:
    ev = InsightsEvidence(
        source_rel="SECURITY-INSIGHTS.yml",
        valid=True,
        signals={"accepts_vulnerability_reports": True, "security_policy_url": None, "security_contacts": []},
    )
    assert ev.declares_vulnerability_reporting_channel() is False


def test_predicate_false_when_not_accepting_reports() -> None:
    ev = InsightsEvidence(
        source_rel="SECURITY-INSIGHTS.yml",
        valid=True,
        signals={"accepts_vulnerability_reports": False, "security_policy_url": "https://x", "security_contacts": []},
    )
    assert ev.declares_vulnerability_reporting_channel() is False


# --- Loader ----------------------------------------------------------------


def test_load_insights_evidence_present_and_valid(tmp_path: Path) -> None:
    (tmp_path / "SECURITY-INSIGHTS.yml").write_text(_INSIGHTS_WITH_CHANNEL, encoding="utf-8")
    ev = load_insights_evidence(tmp_path)
    assert ev is not None
    assert ev.valid is True
    assert ev.source_rel == "SECURITY-INSIGHTS.yml"
    assert ev.declares_vulnerability_reporting_channel() is True


def test_load_insights_evidence_missing_returns_none(tmp_path: Path) -> None:
    assert load_insights_evidence(tmp_path) is None


# --- reports/2.0 projection of the new status ------------------------------


def test_self_attested_maps_to_reports_v2_state() -> None:
    assert map_status_to_reports_v2("self-attested") == ("SELF_ATTESTED", None)


# --- The three allowlisted controls: off -> manual, on -> self-attested ----


def _write_generic_repo(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text(_GENERIC_SECURITY_MD, encoding="utf-8")


def test_gov_disc_013_off_is_manual_on_is_self_attested(tmp_path: Path) -> None:
    _write_generic_repo(tmp_path)
    assert eval_gov_disc_013(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED
    lifted = eval_gov_disc_013(_ctx(tmp_path, insights_evidence=_channel_evidence()))
    assert lifted.status == ControlStatus.SELF_ATTESTED
    assert lifted.extra.get("provenance") == "self-reported"
    assert "SECURITY-INSIGHTS.yml" in lifted.evidence_sources[0]


def test_gov_disc_065_off_is_manual_on_is_self_attested(tmp_path: Path) -> None:
    _write_generic_repo(tmp_path)
    assert eval_gov_disc_065(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED
    lifted = eval_gov_disc_065(_ctx(tmp_path, insights_evidence=_channel_evidence()))
    assert lifted.status == ControlStatus.SELF_ATTESTED
    assert lifted.extra.get("provenance") == "self-reported"


def test_cra_coord_002_off_is_manual_on_is_self_attested(tmp_path: Path) -> None:
    _write_generic_repo(tmp_path)
    assert eval_cra_art14_coord_002(_ctx(tmp_path)).status == ControlStatus.MANUAL_REVIEW_REQUIRED
    lifted = eval_cra_art14_coord_002(_ctx(tmp_path, insights_evidence=_channel_evidence()))
    assert lifted.status == ControlStatus.SELF_ATTESTED
    assert lifted.extra.get("provenance") == "self-reported"


# --- Guard-rail: a self-report NEVER lifts a deterministic FAIL ------------


def test_self_report_does_not_lift_deterministic_fail(tmp_path: Path) -> None:
    # No SECURITY.md at all -> GOV-DISC-013 is a deterministic FAIL. Even with a
    # channel-declaring Insights file present, the FAIL must stand (ADR-033 fence).
    outcome = eval_gov_disc_013(_ctx(tmp_path, insights_evidence=_channel_evidence()))
    assert outcome.status == ControlStatus.FAIL


def test_insights_without_channel_does_not_lift(tmp_path: Path) -> None:
    _write_generic_repo(tmp_path)
    no_channel = InsightsEvidence(
        source_rel="SECURITY-INSIGHTS.yml",
        valid=True,
        signals={"accepts_vulnerability_reports": False, "security_policy_url": None, "security_contacts": []},
    )
    assert eval_gov_disc_013(_ctx(tmp_path, insights_evidence=no_channel)).status == (
        ControlStatus.MANUAL_REVIEW_REQUIRED
    )
