"""CRA controls that pass on documentation, and the evidence they prefer over it.

These controls answer regulatory questions -- did you document secure defaults, do you run
coordinated disclosure, have you classified the product -- and they accept prose because that
is what the Regulation asks for. That makes the passing direction the risky one: a scan that
never matches marks every repository non-compliant, and a scan that matches too loosely marks
every repository compliant. Both halves are asserted for each control.

Where a machine-readable file exists it wins over prose, and the reason says which was used --
`disclosure-policy.json` is higher confidence than a README heading, and an auditor reading the
report needs to know which one backed the verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import cra
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(root: Path) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="cra-eu-conformance-evidence-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(root: Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


# --------------------------------------------------------------------------- #
# CRA Art. 13 — secure defaults
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "phrase",
    ["secure default", "secure-by-default", "default configuration", "hardened default"],
)
def test_documented_secure_defaults_pass(phrase: str, tmp_path: Path) -> None:
    _write(tmp_path, "SECURITY.md", f"## Configuration\n\nWe ship a {phrase} posture.\n")
    outcome = cra.eval_cra_art13_defaults_002(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert "SECURITY.md" in outcome.reason


def test_a_readme_that_says_nothing_about_defaults_does_not_pass(tmp_path: Path) -> None:
    """The counterpart: a scan matching anything would mark every repository compliant."""

    _write(tmp_path, "SECURITY.md", "## Reporting\n\nEmail security@example.com.\n")
    assert cra.eval_cra_art13_defaults_002(_ctx(tmp_path)).status is not ControlStatus.PASS


# --------------------------------------------------------------------------- #
# CRA Art. 14 — coordinated disclosure
# --------------------------------------------------------------------------- #


def test_the_machine_readable_policy_is_preferred_and_named(tmp_path: Path) -> None:
    """Higher confidence than prose, and the reason has to say which one backed the verdict."""

    _write(
        tmp_path,
        ".oss-policy-kit/evidence/disclosure-policy.json",
        json.dumps({"coordinated_disclosure": True}),
    )
    outcome = cra.eval_cra_art14_coord_002(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert "disclosure-policy.json" in outcome.reason
    assert outcome.confidence == "high"


@pytest.mark.parametrize(
    "payload",
    ['{"coordinated_disclosure": false}', '{"coordinated_disclosure": "yes"}', "{}", "{ broken json"],
)
def test_a_policy_file_that_does_not_declare_it_falls_through_to_prose(payload: str, tmp_path: Path) -> None:
    """`is True` on purpose: the string "yes" is not a declaration the kit can rely on."""

    _write(tmp_path, ".oss-policy-kit/evidence/disclosure-policy.json", payload)
    outcome = cra.eval_cra_art14_coord_002(_ctx(tmp_path))
    assert "disclosure-policy.json declares" not in (outcome.reason or "")


@pytest.mark.parametrize(
    "phrase",
    ["coordinated disclosure", "coordinated vulnerability disclosure", "responsible disclosure"],
)
def test_a_documented_disclosure_policy_passes_at_lower_confidence(phrase: str, tmp_path: Path) -> None:
    _write(tmp_path, "SECURITY.md", f"## Reporting\n\nWe follow {phrase}.\n")
    outcome = cra.eval_cra_art14_coord_002(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert outcome.confidence == "medium"


def test_no_disclosure_policy_anywhere_does_not_pass(tmp_path: Path) -> None:
    _write(tmp_path, "SECURITY.md", "## Reporting\n\nEmail us.\n")
    assert cra.eval_cra_art14_coord_002(_ctx(tmp_path)).status is not ControlStatus.PASS


# --------------------------------------------------------------------------- #
# CRA product classification
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "term",
    ["important product", "critical product", "default category", "class i", "annex iii"],
)
def test_a_declared_product_class_passes(term: str, tmp_path: Path) -> None:
    _write(tmp_path, "docs/cra-classification.md", f"# Classification\n\nThis is an {term}.\n")
    outcome = cra.eval_cra_product_class_001(_ctx(tmp_path))
    assert outcome.status is ControlStatus.PASS
    assert "cra-classification.md" in outcome.reason


def test_a_classification_file_that_declares_no_class_does_not_pass(tmp_path: Path) -> None:
    """Having the file is not the claim; naming a class is."""

    _write(tmp_path, "docs/cra-classification.md", "# Classification\n\nTo be completed.\n")
    assert cra.eval_cra_product_class_001(_ctx(tmp_path)).status is not ControlStatus.PASS


def test_no_classification_document_does_not_pass(tmp_path: Path) -> None:
    assert cra.eval_cra_product_class_001(_ctx(tmp_path)).status is not ControlStatus.PASS


# --------------------------------------------------------------------------- #
# Composed secret-scan evidence
# --------------------------------------------------------------------------- #


def _sarif(root: Path, payload: object) -> None:
    _write(
        root,
        ".oss-policy-kit/evidence/sast/gitleaks.sarif.json",
        payload if isinstance(payload, str) else json.dumps(payload),
    )


def test_secret_findings_fail_the_default_credential_control(tmp_path: Path) -> None:
    _sarif(tmp_path, {"runs": [{"results": [{"ruleId": "aws-key"}, {"ruleId": "gh-pat"}]}]})
    outcome = cra.eval_cisa_sbd_secrets_005(_ctx(tmp_path))
    assert outcome.status is ControlStatus.FAIL
    assert "2 secret finding" in outcome.reason


def test_a_clean_secret_scan_does_not_fail(tmp_path: Path) -> None:
    _sarif(tmp_path, {"runs": [{"results": []}]})
    assert cra.eval_cisa_sbd_secrets_005(_ctx(tmp_path)).status is not ControlStatus.FAIL


@pytest.mark.parametrize(
    "payload",
    ['["not", "a", "sarif"]', '{"runs": "not-a-list"}', '{"runs": [{"results": "not-a-list"}]}', "{ broken"],
)
def test_secret_evidence_of_the_wrong_shape_is_not_read_as_clean(payload: str, tmp_path: Path) -> None:
    """A shape the reader cannot count is unknown, and unknown must not be reported as zero."""

    _sarif(tmp_path, payload)
    assert cra.eval_cisa_sbd_secrets_005(_ctx(tmp_path)).status is not ControlStatus.FAIL


def test_no_secret_evidence_at_all_asks_a_human(tmp_path: Path) -> None:
    outcome = cra.eval_cisa_sbd_secrets_005(_ctx(tmp_path))
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "gitleaks.sarif.json" in outcome.reason
