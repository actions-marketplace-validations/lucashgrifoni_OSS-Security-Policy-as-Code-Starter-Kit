"""SEC-CODEQL-010 / SEC-SECRETS-050: expanded CI tool keyword coverage."""

from __future__ import annotations

import pytest

from oss_policy_kit.application.evaluators import EvalContext, eval_sec_codeql_010, eval_sec_secrets_050
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows


def _ctx(repo):
    return EvalContext(
        repo_root=repo,
        profile_id="github-level-1",
        workflows=analyze_workflows(repo),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


@pytest.mark.parametrize(
    "snippet",
    [
        "run: snyk code test",
        "run: bearer scan .",
        "uses: checkmarx/ast-github-action@v2",
        "run: veracode scan",
        "run: spotbugs",
        "run: gosec ./...",
        "run: pip install flake8-bugbear && flake8",
        "uses: sonarsource/sonarcloud-github-action@master",
        "run: sonar-scanner",
        "uses: returntocorp/semgrep-action@v1",
        "uses: zupit/horusec-action@v2",
    ],
)
def test_sec_codeql_010_detects_expanded_sast_tool(tmp_path, snippet: str) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "sast.yml").write_text(
        f"on: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - {snippet}\n",
        encoding="utf-8",
    )
    out = eval_sec_codeql_010(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS


@pytest.mark.parametrize(
    "snippet",
    [
        "run: detect-secrets scan",
        "run: npx secretlint",
        "run: noseyparker scan",
        "run: ggshield secret scan repo",
        "run: gitguardian scan",
        "run: trivy fs . --scanners secret",
        "run: semgrep --config=p/secrets c",
        "run: checkov -d . --check CKV_SECRET_6",
    ],
)
def test_sec_secrets_050_detects_expanded_secret_scanners(tmp_path, snippet: str) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "sec.yml").write_text(
        f"on: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - {snippet}\n",
        encoding="utf-8",
    )
    out = eval_sec_secrets_050(_ctx(tmp_path))
    assert out.status == ControlStatus.PASS
