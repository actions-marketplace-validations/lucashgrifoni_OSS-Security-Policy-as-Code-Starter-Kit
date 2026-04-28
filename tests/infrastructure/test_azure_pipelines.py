"""Azure Pipelines static analysis."""

from pathlib import Path

from tests.conftest import AZURE_HARDENED_FIXTURE, AZURE_MINIMAL_FIXTURE

from oss_policy_kit.application.evaluators import EvalContext, eval_az_ident_036
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def test_minimal_azure_pipeline_detected_with_low_signals() -> None:
    az = analyze_azure_pipelines(AZURE_MINIMAL_FIXTURE)
    assert az.pipeline_paths
    assert not az.pr_validation_paths
    assert not az.extends_template_paths
    assert not az.security_scan_signal_paths


def test_hardened_azure_pipeline_detects_security_and_governance_signals() -> None:
    az = analyze_azure_pipelines(AZURE_HARDENED_FIXTURE)
    assert az.pipeline_paths
    assert az.pr_validation_paths
    assert az.extends_template_paths
    assert az.security_scan_signal_paths
    assert az.dependency_audit_signal_paths
    assert az.sbom_signal_paths
    assert az.azure_deploy_signal_paths
    assert az.workload_identity_signal_paths
    assert not az.persist_credentials_true_paths


def test_add_spn_to_environment_false_alone_is_not_workload_identity_signal(tmp_path: Path) -> None:
    """addSpnToEnvironment: false is not proof of workload identity federation."""

    yml = tmp_path / "azure-pipelines.yml"
    yml.write_text(
        "pool:\n  vmImage: ubuntu-latest\n"
        "steps:\n"
        "  - task: AzureCLI@2\n"
        "    inputs:\n"
        "      azureSubscription: svc\n"
        "      addSpnToEnvironment: false\n"
        "      scriptType: bash\n"
        "      scriptLocation: inlineScript\n"
        "      inlineScript: echo deploy\n",
        encoding="utf-8",
    )
    az = analyze_azure_pipelines(tmp_path)
    assert az.azure_deploy_signal_paths
    assert not az.workload_identity_signal_paths

    out = eval_az_ident_036(
        EvalContext(
            repo_root=tmp_path,
            profile_id="azure-level-2",
            workflows=WorkflowAnalysis(),
            azure_pipelines=az,
            aws_ci=AwsCiAnalysis(),
            scorecard=None,
        )
    )
    assert out.status == ControlStatus.MANUAL_REVIEW_REQUIRED
