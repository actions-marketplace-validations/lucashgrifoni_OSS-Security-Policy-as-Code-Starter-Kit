"""Shared pytest fixtures."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_VULNERABLE = ROOT / "examples" / "vulnerable-repo"
EXAMPLE_HARDENED = ROOT / "examples" / "hardened-repo"
TEST_FIXTURES = ROOT / "tests" / "fixtures"
REPOSITORY_FIXTURES = TEST_FIXTURES / "repositories"
INVALID_WORKFLOW_FIXTURE = REPOSITORY_FIXTURES / "invalid-workflow-target"
REPO_WITH_SPACES_FIXTURE = REPOSITORY_FIXTURES / "repo with spaces"
AZURE_MINIMAL_FIXTURE = REPOSITORY_FIXTURES / "azure-minimal-target"
AZURE_HARDENED_FIXTURE = REPOSITORY_FIXTURES / "azure-hardened-target"
AWS_MINIMAL_FIXTURE = REPOSITORY_FIXTURES / "aws-minimal-target"
AWS_HARDENED_FIXTURE = REPOSITORY_FIXTURES / "aws-hardened-target"


@pytest.fixture
def repo_root_vulnerable() -> Path:
    return EXAMPLE_VULNERABLE


@pytest.fixture
def repo_root_hardened() -> Path:
    return EXAMPLE_HARDENED
