"""Evaluator paths between "no evidence" and "good evidence".

"Cannot tell" is a real answer here and has to stay distinguishable from "no" and from "yes":
collapsing it into a pass overstates the posture, collapsing it into a fail sends someone
chasing a control that may already be satisfied. Three places where that distinction is made:

* a filled-in artifact template with a genuine digest, which has to get past *both* digest
  guards and reach a real verdict;
* a self-hosted runner fleet whose ``runner-groups.json`` is unreadable -- the workflows say
  self-hosted, the evidence says nothing legible, so the answer is a question for a human;
* provenance verification metadata whose ``verified_at`` is missing, blank or not a string,
  which must not be read as a fresh verification.

Three neighbouring branches are deliberately absent because they cannot be reached, each
guarded by the schema one step earlier: the `is_valid_sha256_digest` rejection (see the note
on the digest test), the missing-``runner-groups.json`` arm of GH-RUNNER-062 (the preceding
helper only returns ``None`` when that file exists), and the empty-``runner_groups`` failure
(the schema sets ``minItems: 1``). They are left in the source as defence in depth; inventing
tests that appear to cover them would be worse than leaving them uncovered.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import azure, github
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.application.evidence_placeholders import has_placeholder_values, is_placeholder_digest
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.domain.models import ControlStatus
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis, analyze_workflows

_REAL_DIGEST = "9f2c4e1ab7d0538e6c91af43b2705d8ec1f6a394d20b8e57cf3401d6b7e28405"


def _ctx(root: Path, profile_id: str, *, workflows: WorkflowAnalysis | None = None) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id=profile_id,
        workflows=workflows or WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write_evidence(root: Path, name: str, payload: dict) -> None:
    d = root / ".oss-policy-kit" / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


def _azure_artifact_evidence(root: Path, filename: str, digest: str) -> None:
    """Write the scaffold's own template for *filename*, filled in, with *digest* substituted.

    Building the payload by hand means guessing at the schema; starting from the template the
    kit itself ships means the only thing under test is the digest.
    """

    scaffold_evidence_files(root, "azure")
    path = root / ".oss-policy-kit" / "evidence" / filename
    payload = json.loads(path.read_text(encoding="utf-8"))

    def _fill(node: object) -> object:
        if isinstance(node, str):
            if is_placeholder_digest(node):
                return digest
            return "acme-platform-team" if has_placeholder_values(node) else node
        if isinstance(node, dict):
            return {k: _fill(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_fill(v) for v in node]
        return node

    path.write_text(json.dumps(_fill(payload)), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Artifact digests
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("filename", "evaluate"),
    [
        ("azure-sbom-artifact.json", azure.eval_az_artsbom_058),
        ("azure-provenance-artifact.json", azure.eval_az_artprv_059),
    ],
)
def test_a_well_formed_digest_reaches_a_real_verdict(filename: str, evaluate: object, tmp_path: Path) -> None:
    """A filled-in template with a real digest must get past both digest guards.

    Note on what is *not* tested here: the `is_valid_sha256_digest` guard one line below the
    placeholder check cannot be reached from this path. The schema constrains both digest
    fields to `^[a-f0-9]{64}$`, and every low-entropy pattern that guard rejects is a subset
    of what `is_placeholder_digest` already caught. Verified by search over repeated-unit and
    random digests: no string satisfies schema + not-placeholder + not-valid. The guard is
    left in place as defence in depth against a future schema relaxation.
    """

    _azure_artifact_evidence(tmp_path, filename, _REAL_DIGEST)
    outcome = evaluate(_ctx(tmp_path, "azure-level-3"))  # type: ignore[operator]
    assert outcome.status is not ControlStatus.NOT_EVALUATED


# --------------------------------------------------------------------------- #
# Self-hosted runners with nothing said about isolation
# --------------------------------------------------------------------------- #


def _self_hosted_repo(root: Path) -> WorkflowAnalysis:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(
        "name: ci\n"
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: [self-hosted, ephemeral]\n"
        "    steps:\n"
        "      - run: echo hi\n",
        encoding="utf-8",
    )
    return analyze_workflows(root)


def test_an_unreadable_runner_groups_file_also_asks_a_human(tmp_path: Path) -> None:
    workflows = _self_hosted_repo(tmp_path)
    _write_evidence(tmp_path, "runner-groups.json", {"unexpected": True})
    outcome = github.eval_gh_runner_062(_ctx(tmp_path, "github-level-3", workflows=workflows))
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED
    assert "schema" in outcome.reason.lower()


# --------------------------------------------------------------------------- #
# Provenance verification freshness
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("verified_at", [None, "", "   ", 20260501])
def test_a_verification_without_a_usable_timestamp_is_not_fresh(verified_at: object) -> None:
    """No readable time means no way to know it is recent, so it cannot count as verified."""

    verification = {"transparency_log_inclusion": True, "verified_at": verified_at}
    assert github._immutrel_attested_ok(verification, max_age_days=30) is False


def test_a_verification_missing_its_transparency_log_entry_is_not_fresh() -> None:
    assert github._immutrel_attested_ok({"verified_at": "2026-05-01T00:00:00Z"}, max_age_days=30) is False


def test_verification_metadata_of_the_wrong_type_is_not_fresh() -> None:
    assert github._immutrel_attested_ok("verified", max_age_days=30) is False
