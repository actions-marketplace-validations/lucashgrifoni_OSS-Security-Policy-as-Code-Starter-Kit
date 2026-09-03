"""Reading CI definitions from three ecosystems, and degrading honestly without the HCL parser.

These parsers all read files somebody committed, so they answer two questions at once: what does
this pipeline do, and can the answer be trusted. The second one is where the tests concentrate.

`python-hcl2` is a soft dependency. Without it `scan-iac` reports `not_available` rather than
crashing or, worse, reporting a clean Terraform estate it never read -- and that path can only be
exercised by making the import fail, which is what the fixture here does.
"""

from __future__ import annotations

import builtins
import importlib.util
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from oss_policy_kit.infrastructure import azure_pipeline_parser as azure
from oss_policy_kit.infrastructure.aws_ci_parser import analyze_aws_ci
from oss_policy_kit.infrastructure.iac import hcl_loader

# --------------------------------------------------------------------------- #
# The optional HCL parser
# --------------------------------------------------------------------------- #


@pytest.fixture
def hcl2_missing(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Execute a second, private copy of the loader with `import hcl2` failing.

    The module decides availability once at import, which is the right design -- it must not pay
    an import attempt per file -- and it means the unavailable path only exists at import time.

    A fresh copy rather than `importlib.reload`, and that distinction cost a green suite to
    learn: reloading re-executes in the *same* module dict, so `HclLoadError` becomes a new class
    object while `tf_resource_index`, which imported the name at its own import time, keeps
    catching the old one. The `except HclLoadError` there stopped matching and a parse failure
    escaped `build_index`. Nothing here touches `sys.modules`.
    """

    real_import = builtins.__import__

    def _refuse(name: str, *args: object, **kwargs: object) -> Any:
        if name == "hcl2":
            raise ImportError("No module named 'hcl2'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    spec = importlib.util.spec_from_file_location("_hcl_loader_without_hcl2", hcl_loader.__file__)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)

    monkeypatch.setattr(builtins, "__import__", _refuse)
    spec.loader.exec_module(module)
    monkeypatch.undo()

    yield module


def test_without_the_parser_the_kit_says_so_rather_than_pretending(hcl2_missing: Any) -> None:
    assert hcl2_missing.hcl2_available() is False


def test_without_the_parser_a_terraform_file_is_an_error_not_an_empty_result(hcl2_missing: Any, tmp_path: Path) -> None:
    """An empty parse would read downstream as "no risky resources in this repository"."""

    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")

    with pytest.raises(hcl2_missing.HclLoadError) as excinfo:
        hcl2_missing.load_hcl_file(tf)

    assert "python-hcl2 is not installed" in str(excinfo.value)
    assert excinfo.value.path == tf


def test_with_the_parser_present_the_same_file_parses(tmp_path: Path) -> None:
    """The counterpart, and the proof the fixture left the real module alone."""

    tf = tmp_path / "main.tf"
    tf.write_text('resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n', encoding="utf-8")

    assert hcl_loader.hcl2_available() is True
    assert "resource" in hcl_loader.load_hcl_file(tf)


# --------------------------------------------------------------------------- #
# AWS buildspec env blocks
# --------------------------------------------------------------------------- #


def _buildspec(root: Path, body: str) -> None:
    path = root / "buildspec.yml"
    path.write_text(body, encoding="utf-8")


def test_parameter_store_and_secrets_manager_are_recorded_separately(tmp_path: Path) -> None:
    """They are different postures: one is SSM, the other Secrets Manager, and reports name both."""

    _buildspec(
        tmp_path,
        "version: 0.2\nenv:\n"
        "  parameter-store:\n    DB_PASSWORD: /prod/db/password\n"
        "  secrets-manager:\n    API_KEY: prod/api:key\n"
        "phases:\n  build:\n    commands:\n      - make\n",
    )
    analysis = analyze_aws_ci(tmp_path)

    assert analysis.parameter_store_signal_paths
    assert analysis.secrets_manager_signal_paths


@pytest.mark.parametrize(
    ("label", "env_block"),
    [
        ("declared but empty", "  parameter-store: {}\n  secrets-manager: {}\n"),
        ("declared as a list", "  parameter-store: []\n  secrets-manager: []\n"),
        ("not declared at all", "  variables:\n    LOG_LEVEL: info\n"),
    ],
)
def test_an_empty_or_wrong_shaped_secret_block_is_not_a_signal(label: str, env_block: str, tmp_path: Path) -> None:
    """An empty block is a heading with nothing under it, not evidence of managed secrets."""

    _buildspec(tmp_path, "version: 0.2\nenv:\n" + env_block + "phases:\n  build:\n    commands:\n      - make\n")
    analysis = analyze_aws_ci(tmp_path)

    assert analysis.parameter_store_signal_paths == [], label
    assert analysis.secrets_manager_signal_paths == []


# --------------------------------------------------------------------------- #
# Committed CodePipeline exports
# --------------------------------------------------------------------------- #


def _export(root: Path, name: str, body: str) -> Path:
    path = root / "pipelines" / "aws" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_a_committed_iam_role_in_a_real_export_is_recorded(tmp_path: Path) -> None:
    _export(
        tmp_path,
        "codepipeline.json",
        json.dumps(
            {
                "pipeline": {
                    "name": "release",
                    "roleArn": "arn:aws:iam::123456789012:role/pipeline",
                    "stages": [{"name": "Source"}],
                }
            }
        ),
    )
    analysis = analyze_aws_ci(tmp_path)

    assert analysis.codepipeline_valid_export_paths
    assert analysis.codepipeline_committed_iam_role_paths


def test_a_yaml_export_is_read_as_well_as_a_json_one(tmp_path: Path) -> None:
    """The suffix picks the reader; a YAML export must not be treated as invalid JSON."""

    _export(
        tmp_path,
        "codepipeline.yaml",
        "pipeline:\n"
        "  name: release\n"
        "  roleArn: arn:aws:iam::123456789012:role/pipeline\n"
        "  stages:\n    - name: Source\n",
    )
    analysis = analyze_aws_ci(tmp_path)

    assert analysis.codepipeline_valid_export_paths
    assert analysis.parse_errors == []


def test_a_name_only_stub_is_not_counted_as_an_export(tmp_path: Path) -> None:
    """A stub proves nothing about the pipeline, and counting it would credit an empty file."""

    _export(tmp_path, "codepipeline.json", json.dumps({"pipeline": {"name": "release"}}))
    analysis = analyze_aws_ci(tmp_path)

    assert analysis.codepipeline_valid_export_paths == []
    assert analysis.codepipeline_committed_iam_role_paths == []


def test_an_export_that_does_not_parse_is_recorded_as_a_parse_error(tmp_path: Path) -> None:
    path = _export(tmp_path, "codepipeline.json", "{ not json")
    analysis = analyze_aws_ci(tmp_path)

    assert [p for p, _err in analysis.parse_errors] == [path]
    assert analysis.codepipeline_valid_export_paths == []


def test_a_role_that_is_not_an_iam_arn_is_not_recorded_as_one(tmp_path: Path) -> None:
    """The prefix check is what keeps a placeholder out of the evidence trail."""

    _export(
        tmp_path,
        "codepipeline.json",
        json.dumps({"pipeline": {"name": "release", "roleArn": "TODO", "stages": [{"name": "Source"}]}}),
    )
    analysis = analyze_aws_ci(tmp_path)

    assert analysis.codepipeline_valid_export_paths
    assert analysis.codepipeline_committed_iam_role_paths == []


# --------------------------------------------------------------------------- #
# Azure pipelines
# --------------------------------------------------------------------------- #


def _pipeline(root: Path, body: str) -> Path:
    path = root / "azure-pipelines.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_pipeline_whose_root_is_not_a_mapping_is_a_parse_error(tmp_path: Path) -> None:
    """A list at the root is a file the reader cannot navigate, not a pipeline with no steps."""

    path = _pipeline(tmp_path, "- trigger: main\n- steps: []\n")
    analysis = azure.analyze_azure_pipelines(tmp_path)

    assert [p for p, _err in analysis.parse_errors] == [path]


def test_a_checkout_step_that_persists_credentials_is_recorded(tmp_path: Path) -> None:
    """It leaves the job's token in `.git/config`, where any later step can read it."""

    path = _pipeline(
        tmp_path,
        "trigger:\n  - main\nsteps:\n  - checkout: self\n    persistCredentials: true\n  - script: make\n",
    )
    analysis = azure.analyze_azure_pipelines(tmp_path)

    assert analysis.persist_credentials_true_paths == [path]


@pytest.mark.parametrize("value", ["false", "'false'", "no"])
def test_a_checkout_step_that_does_not_persist_credentials_is_not_recorded(value: str, tmp_path: Path) -> None:
    _pipeline(tmp_path, f"trigger:\n  - main\nsteps:\n  - checkout: self\n    persistCredentials: {value}\n")
    analysis = azure.analyze_azure_pipelines(tmp_path)

    assert analysis.persist_credentials_true_paths == []
