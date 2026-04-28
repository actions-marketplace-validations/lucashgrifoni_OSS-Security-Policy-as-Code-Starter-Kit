"""Optional SBOM/provenance hooks on platform collectors (manual-only today)."""

from __future__ import annotations

from oss_policy_kit.infrastructure.collectors.aws_collector import AWSEvidenceCollector
from oss_policy_kit.infrastructure.collectors.azure_collector import AzureDevOpsEvidenceCollector


def test_azure_collect_sbom_and_provenance_hooks_return_empty() -> None:
    c = AzureDevOpsEvidenceCollector(organization="o", personal_access_token="pat")
    assert c.collect_sbom_artifact("Proj/repo") == []
    assert c.collect_provenance_artifact("Proj/repo") == []


def test_aws_collect_sbom_and_provenance_hooks_return_empty() -> None:
    c = AWSEvidenceCollector()
    assert c.collect_sbom_artifact("my-repo") == []
    assert c.collect_provenance_artifact("my-repo") == []
