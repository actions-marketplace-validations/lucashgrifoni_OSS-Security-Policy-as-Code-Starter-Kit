"""AZ-PIPE-028: PR trigger detection — structural YAML only (no raw-string false positives)."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.azure_pipeline_parser import analyze_azure_pipelines


def _write_pipeline(tmp_path: Path, content: str) -> None:
    (tmp_path / "azure-pipelines.yml").write_text(content, encoding="utf-8")


def test_az_pipe028_detects_pr_trigger_structural(tmp_path: Path) -> None:
    """Pipeline with top-level pr: key is flagged as having PR validation."""
    _write_pipeline(
        tmp_path,
        """\
trigger:
  branches:
    include:
      - main

pr:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - script: echo build
""",
    )
    az = analyze_azure_pipelines(tmp_path)
    assert az.pr_validation_paths, "expected pr: key to be detected"


def test_az_pipe028_not_detected_when_pr_in_comment_only(tmp_path: Path) -> None:
    """pr: in a YAML comment must NOT be flagged — this proves the structural upgrade."""
    _write_pipeline(
        tmp_path,
        """\
# pr: validation is handled by branch policies externally
trigger:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - script: echo build
""",
    )
    az = analyze_azure_pipelines(tmp_path)
    assert not az.pr_validation_paths, "pr: in a YAML comment must not trigger detection"


def test_az_pipe028_not_detected_without_pr_key(tmp_path: Path) -> None:
    """Pipeline without a pr: key is not flagged."""
    _write_pipeline(
        tmp_path,
        """\
trigger:
  branches:
    include:
      - main

pool:
  vmImage: ubuntu-latest

steps:
  - script: echo build
""",
    )
    az = analyze_azure_pipelines(tmp_path)
    assert not az.pr_validation_paths


def test_az_pipe028_not_detected_when_pr_appears_in_description_string(tmp_path: Path) -> None:
    """pr: substring in a YAML string value must not trigger detection."""
    _write_pipeline(
        tmp_path,
        """\
trigger:
  branches:
    include:
      - main

variables:
  buildDescription: "run on pr: validation pipeline"

pool:
  vmImage: ubuntu-latest

steps:
  - script: echo build
""",
    )
    az = analyze_azure_pipelines(tmp_path)
    # The structural parser checks data.get("pr") not raw string; this must not be flagged
    assert not az.pr_validation_paths
