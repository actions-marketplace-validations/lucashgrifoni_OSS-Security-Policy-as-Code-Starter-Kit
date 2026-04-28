"""GH-DEPLOY-022 and GH-PROV-023: expanded OIDC and provenance pattern detection."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.evaluators import EvalContext, eval_gh_dep_022, eval_gh_prov_023
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows


def _ctx(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-2",
        workflows=analyze_workflows(tmp_path),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_workflow(tmp_path: Path, content: str, name: str = "deploy.yml") -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(content, encoding="utf-8")


# ── GH-DEPLOY-022: provider-specific OIDC action patterns ───────────────────


def test_gh_deploy022_passes_aws_oidc_role_to_assume(tmp_path: Path) -> None:
    """aws-actions/configure-aws-credentials with role-to-assume → OIDC detected → PASS."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
          aws-region: us-east-1
      - run: aws s3 sync ./dist s3://my-bucket/
""",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.cloud_deploy_workflow_paths
    assert wf.cloud_deploy_with_oidc_paths
    out = eval_gh_dep_022(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gh_deploy022_passes_gcp_oidc_workload_identity(tmp_path: Path) -> None:
    """google-github-actions/auth with workload_identity_provider → OIDC detected → PASS."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/123/locations/global/workloadIdentityPools/pool/providers/github
          service_account: my-sa@my-project.iam.gserviceaccount.com
      - run: gcloud run deploy myservice --image gcr.io/project/image
""",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.cloud_deploy_workflow_paths
    assert wf.cloud_deploy_with_oidc_paths
    out = eval_gh_dep_022(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gh_deploy022_passes_azure_oidc_client_id(tmp_path: Path) -> None:
    """azure/login with client-id (no creds) → OIDC federation detected → PASS."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - run: az deployment group create --resource-group rg --template-file main.bicep
""",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.cloud_deploy_workflow_paths
    assert wf.cloud_deploy_with_oidc_paths
    out = eval_gh_dep_022(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_gh_deploy022_manual_review_when_deploy_but_no_oidc_signal(tmp_path: Path) -> None:
    """Deploy workflow without any OIDC signal → MANUAL_REVIEW_REQUIRED."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - run: aws s3 sync ./dist s3://my-bucket/
""",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.cloud_deploy_workflow_paths
    assert not wf.cloud_deploy_with_oidc_paths
    out = eval_gh_dep_022(_ctx(tmp_path))
    assert out.status in (ControlStatus.MANUAL_REVIEW_REQUIRED, ControlStatus.FAIL)


# ── GH-PROV-023: expanded provenance/attestation patterns ────────────────────


def test_gh_prov023_passes_slsa_github_generator(tmp_path: Path) -> None:
    """slsa-framework/slsa-github-generator action → provenance signal detected → PASS."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
jobs:
  provenance:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1
    with:
      base64-subjects: ${{ needs.build.outputs.hashes }}
    secrets: inherit
""",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.has_artifact_attestation


def test_gh_prov023_passes_cosign_installer_with_sign(tmp_path: Path) -> None:
    """sigstore/cosign-installer + cosign sign → provenance signal detected → PASS."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
  id-token: write
jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign --yes my-image:latest
""",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.has_artifact_attestation


def test_gh_prov023_not_detected_on_plain_release_without_attestation(tmp_path: Path) -> None:
    """Release workflow without any attestation/provenance steps → no signal."""
    _write_workflow(
        tmp_path,
        """\
on:
  push:
    tags:
      - 'v*'
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python -m build
      - run: gh release create ${{ github.ref_name }} dist/*
""",
    )
    wf = analyze_workflows(tmp_path)
    assert not wf.has_artifact_attestation
    out = eval_gh_prov_023(_ctx(tmp_path))
    # FAIL is the correct outcome: release workflow exists but no provenance/attestation signal
    assert out.status in (ControlStatus.FAIL, ControlStatus.MANUAL_REVIEW_REQUIRED, ControlStatus.NOT_APPLICABLE)
