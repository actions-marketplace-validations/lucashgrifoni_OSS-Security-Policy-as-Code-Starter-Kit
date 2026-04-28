"""Workflow static analysis."""

from pathlib import Path

from tests.conftest import EXAMPLE_HARDENED, EXAMPLE_VULNERABLE

from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows


def test_vulnerable_mutable_and_dangerous() -> None:
    wf = analyze_workflows(EXAMPLE_VULNERABLE)
    assert wf.workflow_paths
    assert wf.uses_pull_request_target
    assert wf.mutable_action_refs
    assert wf.missing_top_level_permissions


def test_sast_signal_rejects_echo_semgrep_string_decoy(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "noop.yml").write_text(
        """
name: noop
on: workflow_dispatch
permissions:
  contents: read
jobs:
  noop:
    runs-on: ubuntu-latest
    steps:
      - name: echo semgrep string
        run: echo "semgrep is nice"
""",
        encoding="utf-8",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.sast_ci_signals == []
    assert not wf.has_codeql_or_security_scan


def test_hardened_workflows_cleaner() -> None:
    wf = analyze_workflows(EXAMPLE_HARDENED)
    assert wf.workflow_paths
    assert not wf.uses_pull_request_target
    assert not wf.mutable_action_refs
    assert not wf.missing_top_level_permissions
    assert wf.has_codeql_or_security_scan
    assert wf.has_dependency_review


def test_parser_detects_v2_signals(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "release.yml").write_text(
        """
name: release
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  reusable-deploy:
    uses: org/reusable/.github/workflows/deploy.yml@main
    secrets: inherit
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
""",
        encoding="utf-8",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.reusable_secrets_inherit_paths
    assert wf.pr_self_hosted_runner_paths == []
    assert wf.broad_job_permissions
    assert wf.release_workflow_paths
    assert wf.release_workflows_missing_concurrency
    assert wf.cloud_deploy_workflow_paths
    assert not wf.cloud_deploy_with_oidc_paths


def test_parser_detects_oidc_and_attestation(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    (wf_dir / "deploy.yml").write_text(
        """
name: deploy
on:
  pull_request:
permissions:
  contents: read
  id-token: write
concurrency:
  group: deploy-${{ github.ref }}
  cancel-in-progress: true
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/attest-build-provenance@v1
      - uses: aws-actions/configure-aws-credentials@d42f54716b0e7d3e56f67abce21274ff456b5e03
""",
        encoding="utf-8",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.cloud_deploy_workflow_paths
    assert wf.cloud_deploy_with_oidc_paths
    assert wf.has_artifact_attestation
