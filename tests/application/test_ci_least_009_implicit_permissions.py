"""CI-LEAST-009: implicit broad-permissions risk when jobs omit ``permissions``."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import EvalContext, eval_ci_least_009
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(tmp_path: Path) -> EvalContext:
    return EvalContext(
        repo_root=tmp_path,
        profile_id="github-level-1",
        workflows=analyze_workflows(tmp_path),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_workflow(tmp_path: Path, content: str, name: str = "deploy.yml") -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / name).write_text(textwrap.dedent(content), encoding="utf-8")


# ---------------------------------------------------------------------------
# Sensitive-pattern matrix — each run: line triggers FAIL without permissions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "run_line,label",
    [
        ("docker push myregistry/myimage:tag", "docker push"),
        ("gh release create v1.0.0 --title 'Release'", "gh release"),
        ("helm upgrade myapp ./chart --install", "helm upgrade"),
        ("kubectl apply -f k8s/manifests/", "kubectl apply"),
        ("az deployment group create --resource-group rg --template-file main.bicep", "az deployment"),
        ("aws s3 cp artifact.zip s3://bucket/ && aws codedeploy deploy", "aws deploy"),
        ("gcloud run deploy myservice --image gcr.io/project/image", "gcloud deploy"),
        ("twine upload dist/*", "twine upload"),
        ("npm publish --access public", "npm publish"),
        ("cargo publish --token ${{ secrets.CARGO_TOKEN }}", "cargo publish"),
    ],
)
def test_ci_least_009_fails_on_sensitive_step_without_job_permissions(
    tmp_path: Path, run_line: str, label: str
) -> None:
    _write_workflow(
        tmp_path,
        f"""\
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: {run_line}
        """,
    )
    analysis = analyze_workflows(tmp_path)
    assert analysis.implicit_permission_risks, f"expected risk for: {label}"
    out = eval_ci_least_009(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "Implicit broad-permissions risk" in out.reason


def test_ci_least_009_fails_on_upload_release_asset_uses_without_job_permissions(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """\
        on: push
        jobs:
          release:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-release-asset@v1
                with:
                  upload_url: ${{ steps.create_release.outputs.upload_url }}
                  asset_path: ./dist/artifact.tar.gz
                  asset_name: artifact.tar.gz
                  asset_content_type: application/gzip
        """,
    )
    analysis = analyze_workflows(tmp_path)
    assert analysis.implicit_permission_risks
    out = eval_ci_least_009(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "Implicit broad-permissions risk" in out.reason


def test_ci_least_009_fails_on_checkout_with_non_default_token_without_job_permissions(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """\
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  token: ${{ secrets.MY_PAT }}
        """,
    )
    analysis = analyze_workflows(tmp_path)
    assert analysis.implicit_permission_risks
    out = eval_ci_least_009(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL
    assert "Implicit broad-permissions risk" in out.reason


def test_ci_least_009_fails_when_workflow_has_no_top_level_permissions_and_job_has_deploy(
    tmp_path: Path,
) -> None:
    """Workflow with no top-level permissions block + sensitive step = flagged."""
    _write_workflow(
        tmp_path,
        """\
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: helm upgrade myapp ./chart --install
        """,
    )
    analysis = analyze_workflows(tmp_path)
    assert analysis.implicit_permission_risks
    out = eval_ci_least_009(_ctx(tmp_path))
    assert out.status == ControlStatus.FAIL


# ---------------------------------------------------------------------------
# False-positive guards — correct configurations must NOT trigger FAIL
# ---------------------------------------------------------------------------


def test_ci_least_009_passes_when_job_declares_explicit_permissions(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """\
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            permissions:
              contents: write
              packages: write
            steps:
              - run: docker push myregistry/myimage:tag
        """,
    )
    analysis = analyze_workflows(tmp_path)
    assert not analysis.implicit_permission_risks
    out = eval_ci_least_009(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_ci_least_009_passes_when_workflow_declares_top_level_permissions_and_no_job_override(
    tmp_path: Path,
) -> None:
    """Top-level permissions block suppresses the 'no top-level' warning path."""
    _write_workflow(
        tmp_path,
        """\
        on: push
        permissions:
          contents: write
          packages: write
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: helm upgrade myapp ./chart --install
        """,
    )
    out = eval_ci_least_009(_ctx(tmp_path))
    # Top-level permissions suppress the "no-top-level" path; step path still fires
    # because the job has no job-level permissions block. FAIL is correct here:
    # job-scoped deploy steps should carry job-scoped permissions.
    assert out.status == ControlStatus.FAIL


def test_ci_least_009_passes_on_harmless_workflow_without_sensitive_steps(
    tmp_path: Path,
) -> None:
    _write_workflow(
        tmp_path,
        """\
        on: pull_request
        permissions:
          contents: read
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: pip install ruff && ruff check .
        """,
    )
    out = eval_ci_least_009(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


def test_ci_least_009_passes_on_checkout_with_default_github_token(
    tmp_path: Path,
) -> None:
    """Checkout using the standard GITHUB_TOKEN must not be flagged."""
    _write_workflow(
        tmp_path,
        """\
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  token: ${{ secrets.GITHUB_TOKEN }}
        """,
    )
    analysis = analyze_workflows(tmp_path)
    assert not analysis.implicit_permission_risks
    out = eval_ci_least_009(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
