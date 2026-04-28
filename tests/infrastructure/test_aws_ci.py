"""AWS CodeBuild / CodePipeline static discovery."""

from pathlib import Path

from tests.conftest import AWS_HARDENED_FIXTURE, AWS_MINIMAL_FIXTURE

from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci


def test_minimal_aws_buildspec_only_low_signals() -> None:
    aws = analyze_aws_ci(AWS_MINIMAL_FIXTURE)
    assert aws.buildspec_paths
    assert not aws.codepipeline_paths
    assert not aws.parameter_store_signal_paths
    assert not aws.security_scan_signal_paths


def test_hardened_aws_detects_managed_secrets_scans_pipeline_file() -> None:
    aws = analyze_aws_ci(AWS_HARDENED_FIXTURE)
    assert aws.buildspec_paths
    assert aws.codepipeline_paths
    assert aws.codepipeline_valid_export_paths
    assert aws.codepipeline_committed_iam_role_paths
    assert aws.parameter_store_signal_paths
    assert aws.secrets_manager_signal_paths
    assert aws.security_scan_signal_paths
    assert aws.dependency_audit_signal_paths
    assert aws.sbom_signal_paths
    assert aws.provenance_signal_paths
    assert not aws.inline_secret_risk_paths


def test_aws_access_key_id_detected_with_uppercase_akia(tmp_path: Path) -> None:
    """AKIA pattern must match case-sensitive access key IDs (not lowercased text)."""

    spec = tmp_path / "buildspec.yml"
    spec.write_text(
        "version: 0.2\nphases:\n  build:\n    commands:\n      - echo AKIA1234567890ABCDEF\n",
        encoding="utf-8",
    )
    aws = analyze_aws_ci(tmp_path)
    assert spec.resolve() in {p.resolve() for p in aws.inline_secret_risk_paths}
