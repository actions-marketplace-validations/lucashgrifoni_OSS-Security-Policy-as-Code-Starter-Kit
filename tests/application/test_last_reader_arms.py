"""The final unexercised arms: API-attested Azure evidence, and five small renderers.

The Azure pair is the substantive half. Both controls distinguish evidence the API *produced*
from evidence the API *proved*: `collect-evidence` can reach Azure DevOps, be refused on one of
the four reads it needs, and still write a well-formed file. Trusting the `live` label alone
would report a verified posture built on data nobody could fetch, so the controls check
`posture_support` and drop to `manual-review-required` when it is short -- an outcome that is
strictly weaker than the self-attested one, because the file claims more than it can show.

The renderers below each have a with-and-without arm that changes what an operator reads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.evaluators import azure
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.application.profile_hints import _azure_pipeline_paths
from oss_policy_kit.cli import ingest_insights
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.iac.bicep.scanner import run_scan as run_bicep_scan
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis

runner = CliRunner()

_SUPPORT_KEYS = (
    "pipelines_api_reachable",
    "environments_api_reachable",
    "service_endpoints_api_verified",
    "environment_approval_checks_observable",
)
_STRICT_POSTURE = {
    "approvals_required": True,
    "environment_checks_enabled": True,
    "service_connection_restricted": True,
    "federated_identity_preferred": True,
}


def _ctx(root: Path) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="azure-level-3",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _governance(root: Path, *, live: bool, support: dict[str, bool] | None) -> None:
    payload: dict[str, Any] = {
        "schema_version": "azure-pipeline-governance/v1",
        "attested_at": "2026-08-11",
        "attested_by": "azure-devops-api-collection" if live else "platform-team",
        "project": "contoso/main",
        "posture": dict(_STRICT_POSTURE),
    }
    if support is not None:
        payload["posture_support"] = support
    path = root / ".oss-policy-kit" / "evidence" / "azure-pipeline-governance.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


# --------------------------------------------------------------------------- #
# API-attested, but not API-proven
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("withheld", _SUPPORT_KEYS)
def test_one_unreachable_azure_read_costs_the_verified_verdict(withheld: str, tmp_path: Path) -> None:
    """All four reads back the claim; any one of them missing makes it unproven, not weaker."""

    support = dict.fromkeys(_SUPPORT_KEYS, True) | {withheld: False}
    _governance(tmp_path, live=True, support=support)
    outcome = azure.eval_az_plat_035(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "posture_support" in outcome.reason
    assert outcome.evidence_collection_method is EvidenceCollectionMethod.LIVE


def test_api_attested_evidence_with_no_support_block_is_not_taken_at_its_word(tmp_path: Path) -> None:
    """The `live` label is a claim about how the file was made, not about what was reachable."""

    _governance(tmp_path, live=True, support=None)
    assert azure.eval_az_plat_035(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_fully_supported_api_evidence_passes(tmp_path: Path) -> None:
    _governance(tmp_path, live=True, support=dict.fromkeys(_SUPPORT_KEYS, True))
    assert azure.eval_az_plat_035(_ctx(tmp_path)).status is ControlStatus.PASS


def test_a_hand_written_file_is_self_attested_rather_than_unproven(tmp_path: Path) -> None:
    """It never claimed the APIs were read, so there is nothing to be short of."""

    _governance(tmp_path, live=False, support=None)
    assert azure.eval_az_plat_035(_ctx(tmp_path)).status is ControlStatus.SELF_ATTESTED


@pytest.mark.parametrize("withheld", _SUPPORT_KEYS)
def test_federation_claimed_on_partial_api_data_is_not_confirmed(withheld: str, tmp_path: Path) -> None:
    """Workload identity federation is the strongest identity claim the kit records."""

    support = dict.fromkeys(_SUPPORT_KEYS, True) | {withheld: False}
    _governance(tmp_path, live=True, support=support)
    outcome = azure.eval_az_ident_036(_ctx(tmp_path))

    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "posture_support" in outcome.reason


def test_federation_backed_by_complete_api_data_passes(tmp_path: Path) -> None:
    _governance(tmp_path, live=True, support=dict.fromkeys(_SUPPORT_KEYS, True))
    assert azure.eval_az_ident_036(_ctx(tmp_path)).status is ControlStatus.PASS


def test_federation_claimed_by_hand_is_self_attested(tmp_path: Path) -> None:
    _governance(tmp_path, live=False, support=None)
    assert azure.eval_az_ident_036(_ctx(tmp_path)).status is ControlStatus.SELF_ATTESTED


# --------------------------------------------------------------------------- #
# Pipelines found by more than one pattern
# --------------------------------------------------------------------------- #


def test_a_pipeline_matched_by_two_patterns_is_listed_once(tmp_path: Path) -> None:
    """`azure-pipelines.yml` matches both the exact name and the glob; it is one file."""

    (tmp_path / "azure-pipelines.yml").write_text("trigger: [main]\n", encoding="utf-8")
    (tmp_path / "azure-pipelines-release.yml").write_text("trigger: [main]\n", encoding="utf-8")

    found = _azure_pipeline_paths(tmp_path)

    assert sorted(p.name for p in found) == ["azure-pipelines-release.yml", "azure-pipelines.yml"]
    assert len(found) == len(set(found))


# --------------------------------------------------------------------------- #
# Small renderers with a with-and-without arm
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "rendered"),
    [
        (None, "(not declared)"),
        (True, "true"),
        (False, "false"),
        ([], "(none listed)"),
        (["a", "b"], "a, b"),
        ("text", "text"),
        (7, "7"),
    ],
)
def test_an_undeclared_signal_says_so_rather_than_rendering_empty(value: Any, rendered: str) -> None:
    """`None` and `[]` are different: nothing was declared, versus declared and empty."""

    assert ingest_insights._fmt_signal(value) == rendered


def _snapshot(root: Path) -> Path:
    """A minimal but valid kit data directory to diff the bundled catalog against."""

    (root / "controls").mkdir(parents=True, exist_ok=True)
    (root / "controls" / "catalog.yaml").write_text(
        "schema_version: oss-policy-kit/catalog/v1\n"
        "controls:\n"
        "  - id: GOV-SEC-001\n"
        "    title: Security policy present\n"
        "    category: governance\n"
        "    severity: high\n",
        encoding="utf-8",
    )
    prof = root / "profiles" / "p1"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "profile.yaml").write_text("id: p1\ntitle: P1\ncontrols:\n  - GOV-SEC-001\n", encoding="utf-8")
    return root


def test_diff_catalogs_renders_json_when_asked(tmp_path: Path) -> None:
    snap = _snapshot(tmp_path / "snap")
    result = runner.invoke(app, ["diff-catalogs", "--from", str(snap), "--format", "json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)


def test_diff_catalogs_renders_prose_by_default(tmp_path: Path) -> None:
    """The counterpart: a human default that emitted JSON would be unreadable in a terminal."""

    snap = _snapshot(tmp_path / "snap")
    result = runner.invoke(app, ["diff-catalogs", "--from", str(snap)])

    assert result.exit_code == 0, result.output
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.stdout)


def test_the_osps_coverage_report_lists_its_gaps_by_family() -> None:
    """The gap list is the honest half of that command; printing the heading alone would not be."""

    result = runner.invoke(app, ["osps-coverage"])

    assert result.exit_code == 0, result.output
    assert "Honest gaps:" in result.stdout


def test_a_diagnostic_setting_with_no_scope_covers_nothing(tmp_path: Path) -> None:
    """The pairing is matched on a `scope:` symbol; without one there is nothing to pair to."""

    body = (
        "resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
        "  name: 'appstorage'\n"
        "}\n"
        "resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {\n"
        "  name: 'orphan-diag'\n"
        "}\n"
    )
    (tmp_path / "main.bicep").write_text(body, encoding="utf-8")

    assert "IAC-BICEP-005" in {f.rule_id for f in run_bicep_scan(tmp_path).findings}


# --------------------------------------------------------------------------- #
# Evidence that is valid but unfilled
# --------------------------------------------------------------------------- #


def test_ai_agent_evidence_left_holding_a_scaffold_token_is_refused(tmp_path: Path) -> None:
    """It passes its schema and still attests nothing: `REPLACE_ME` is not an attester."""

    from oss_policy_kit.application.evaluators._shared import _load_ai_agent_evidence

    path = tmp_path / ".oss-policy-kit" / "evidence" / "ai-agent" / "memory-policy.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "ai-agent-baseline/v1",
                "control_id": "AI-AGENT-009",
                "attested_at": "2026-08-11",
                "attested_by": "REPLACE_ME",
            }
        ),
        encoding="utf-8",
    )

    _evidence, data, outcome = _load_ai_agent_evidence(_ctx(tmp_path), "memory-policy.json", "AI agent memory policy")

    assert data is None
    assert outcome is not None
    assert outcome.status is ControlStatus.NOT_EVALUATED
    assert outcome.operational_warnings, "the operator has to be told the file is still a template"


def test_runner_group_evidence_left_holding_a_scaffold_token_is_refused(tmp_path: Path) -> None:
    """Same shape on a different control: an unfilled template must not certify a runner group."""

    from oss_policy_kit.application.evaluators import github

    path = tmp_path / ".oss-policy-kit" / "evidence" / "runner-groups.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "runner-groups/v1",
                "attested_at": "2026-08-11",
                "attested_by": "REPLACE_ME",
                "org_name": "contoso",
                "runner_groups": [
                    {
                        "name": "default",
                        "restricted_to_private_repos": True,
                        "allows_public_repositories": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n", encoding="utf-8")

    ctx = EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-3",
        workflows=WorkflowAnalysis(workflow_paths=[workflow]),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )
    outcome = github.eval_gh_runner_062(ctx)

    assert outcome.status is ControlStatus.NOT_EVALUATED
    assert "REPLACE_ME" in " ".join(outcome.operational_warnings)


def test_a_cloudformation_intrinsic_over_a_mapping_node_is_re_encoded() -> None:
    """`!Fn::If`-style tags carry mappings; the long form has to survive the round trip."""

    import yaml as yaml_module

    from oss_policy_kit.infrastructure.iac.cfn.scanner import _CfnSafeLoader, _intrinsic_constructor

    loader = _CfnSafeLoader("{}")
    node = yaml_module.compose("Key: value")
    ctor = _intrinsic_constructor("Fn::If")

    assert ctor(loader, node) == {"Fn::If": {"Key": "value"}}
