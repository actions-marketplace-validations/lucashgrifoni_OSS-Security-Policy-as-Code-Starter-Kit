"""The last unexercised branches, each stated as the property it protects.

Nothing here shares a theme except the reason they were left: they are the second arm of a check
whose first arm every other test happened to take. That is the coverage gap worth closing, since
a guard nobody has taken is a guard nobody has verified -- and several of these decide whether a
control sees evidence at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from oss_policy_kit.application import loader as loader_module
from oss_policy_kit.application.evaluators import ai, governance
from oss_policy_kit.application.evaluators._shared import (
    EvalContext,
    _detect_spdx_version,
    _iter_ai_agent_text_files,
    _load_ai_agent_evidence,
    _parse_sarif_findings,
)
from oss_policy_kit.application.evidence_placeholders import is_placeholder_digest
from oss_policy_kit.application.evidence_scaffold import _select_evidence_templates
from oss_policy_kit.application.finding_sarif import _load_runs, _project_runs
from oss_policy_kit.application.loader import LoadError, load_catalog
from oss_policy_kit.domain.errors import InvalidInputError
from oss_policy_kit.domain.models import ControlStatus, EvidenceCollectionMethod
from oss_policy_kit.infrastructure.aws_ci_parser import AwsCiAnalysis
from oss_policy_kit.infrastructure.azure_pipeline_parser import AzurePipelineAnalysis
from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis


def _ctx(root: Path) -> EvalContext:
    return EvalContext(
        repo_root=root,
        profile_id="ai-agent-security-1",
        workflows=WorkflowAnalysis(),
        azure_pipelines=AzurePipelineAnalysis(),
        aws_ci=AwsCiAnalysis(),
        scorecard=None,
    )


def _write(root: Path, rel: str, body: str = "x") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Placeholder digests the template list does not name
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("char", ["d", "e", "9", "1"])
def test_any_single_repeated_character_is_a_placeholder(char: str) -> None:
    """The known-template list covers a/b/c/0/f; the entropy check covers whoever typed the rest."""

    assert is_placeholder_digest(char * 64) is True


def test_a_real_digest_is_not_a_placeholder() -> None:
    assert is_placeholder_digest("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") is False


# --------------------------------------------------------------------------- #
# Scaffolding evidence for a platform
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("platform", ["github", "gitlab", "azure", "aws"])
def test_every_supported_platform_has_templates(platform: str) -> None:
    """A platform accepted by `--platform` but unwired here would scaffold an empty directory."""

    assert _select_evidence_templates(platform, "2026-08-11")


def test_a_platform_with_no_templates_is_refused_by_name() -> None:
    with pytest.raises(InvalidInputError, match="github, gitlab, azure, aws"):
        _select_evidence_templates("bitbucket", "2026-08-11")


# --------------------------------------------------------------------------- #
# SARIF that must not be parsed
# --------------------------------------------------------------------------- #


def test_a_sarif_nested_past_the_parser_limit_is_a_message_not_a_crash(tmp_path: Path) -> None:
    """`json.loads` raises RecursionError here, which is not a decode error and not a ValueError."""

    path = _write(tmp_path, "deep.sarif.json", "[" * 3000 + "]" * 3000)
    runs, error = _load_runs(path)

    assert runs is None
    assert error is not None
    assert "too deeply nested" in error


def test_the_first_foreign_driver_is_the_one_reported() -> None:
    """Attribution is decided once; a second run must not overwrite who produced the document."""

    runs = [
        {"tool": {"driver": {"name": "trivy"}}, "results": []},
        {"tool": {"driver": {"name": "grype"}}, "results": []},
    ]
    assert _project_runs(runs, "semgrep", "sast.sarif").foreign_driver == "trivy"


def test_runs_that_are_not_objects_are_counted_as_nothing(tmp_path: Path) -> None:
    path = _write(tmp_path, "zizmor.sarif.json", json.dumps({"runs": ["nope", 42, None]}))
    levels, error = _parse_sarif_findings(path)

    assert error is None
    assert levels == {"error": 0, "warning": 0, "note": 0, "none": 0}


def test_a_well_formed_run_beside_them_is_still_counted(tmp_path: Path) -> None:
    """One unreadable run must not cost the report every finding in the run next to it."""

    doc = {
        "runs": [
            "nope",
            {"tool": {"driver": {"name": "zizmor"}}, "results": [{"ruleId": "R1", "level": "error"}]},
        ]
    }
    path = _write(tmp_path, "zizmor.sarif.json", json.dumps(doc))
    levels, error = _parse_sarif_findings(path)

    assert error is None
    assert levels is not None and levels["error"] == 1


# --------------------------------------------------------------------------- #
# SPDX detection that stops short
# --------------------------------------------------------------------------- #


def test_a_json_ld_document_mentioning_spdx_without_a_version_is_not_claimed_as_spdx_3() -> None:
    """It looks like SPDX 3 at a glance; without a version the kit will not name one."""

    assert _detect_spdx_version('{"@context": {"vocab": "https://example.org/spdx-like"}}') is None


# --------------------------------------------------------------------------- #
# Files the AI-agent text scan walks past
# --------------------------------------------------------------------------- #


def test_the_text_scan_skips_the_directories_that_are_not_the_project(tmp_path: Path) -> None:
    """`node_modules` and `.venv` are somebody else's code, and they dwarf the repository."""

    _write(tmp_path, "node_modules/pkg/index.js", "console.log(1)\n")
    _write(tmp_path, ".venv/lib/site.py", "x = 1\n")
    _write(tmp_path, "src/agent.py", "x = 1\n")

    assert [p.name for p in _iter_ai_agent_text_files(tmp_path)] == ["agent.py"]


def test_a_directory_named_like_a_source_file_is_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "weird.py").mkdir()
    assert _iter_ai_agent_text_files(tmp_path) == []


@pytest.mark.parametrize(
    ("control", "rel"),
    [(ai.eval_llm_218a_pw_002, "tests/test_prompt_injection.py"), (ai.eval_ai_agent_004, "tests/test_jailbreak.py")],
)
def test_a_directory_named_like_a_test_file_does_not_pass_a_control(control: Any, rel: str, tmp_path: Path) -> None:
    """Only a real file is a test; a directory with the right name proves nothing."""

    (tmp_path / rel).mkdir(parents=True)
    assert control(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# AI-agent evidence that cannot be used
# --------------------------------------------------------------------------- #


def test_ai_agent_evidence_that_fails_its_schema_is_refused_with_the_reason(tmp_path: Path) -> None:
    _write(tmp_path, ".oss-policy-kit/evidence/ai-agent/memory-policy.json", json.dumps({"schema_version": "wrong"}))
    _evidence, data, outcome = _load_ai_agent_evidence(_ctx(tmp_path), "memory-policy.json", "AI agent memory policy")

    assert data is None
    assert outcome is not None
    assert outcome.status is ControlStatus.MANUAL_REVIEW_REQUIRED


def test_ai_agent_evidence_left_as_a_scaffold_is_refused(tmp_path: Path) -> None:
    """A template nobody filled in must not be read as a policy somebody wrote."""

    _write(
        tmp_path,
        ".oss-policy-kit/evidence/ai-agent/memory-policy.json",
        json.dumps(
            {
                "schema_version": "ai-agent-baseline/v1",
                "attested_at": "2026-08-11",
                "attested_by": "REPLACE_ME",
                "posture": {"memory_scoped_per_session": True},
            }
        ),
    )
    _evidence, data, outcome = _load_ai_agent_evidence(_ctx(tmp_path), "memory-policy.json", "AI agent memory policy")

    assert data is None
    assert outcome is not None


# --------------------------------------------------------------------------- #
# How evidence says when and how it was collected
# --------------------------------------------------------------------------- #


def test_a_collection_block_timestamp_wins_over_the_attestation_date() -> None:
    """When the API collected it is a fact about the data; when it was attested is not."""

    data = {"collection": {"collected_at": "2026-08-11T09:00:00Z"}, "attested_at": "2026-01-01"}
    assert governance._evidence_timestamp(data) == "2026-08-11T09:00:00Z"


@pytest.mark.parametrize(
    ("label", "collection"),
    [
        ("no collected_at", {"evidence_collection_method": "live"}),
        ("collected_at is blank", {"collected_at": "   "}),
        ("collected_at is not a string", {"collected_at": 20260811}),
    ],
)
def test_an_unusable_collection_timestamp_falls_through_to_the_top_level(
    label: str, collection: dict[str, Any]
) -> None:
    data = {"collection": collection, "attested_at": "2026-01-01"}
    assert governance._evidence_timestamp(data) == "2026-01-01", label


@pytest.mark.parametrize(
    ("declared", "expected"),
    [
        ("live", EvidenceCollectionMethod.LIVE),
        ("manual", EvidenceCollectionMethod.MANUAL),
        ("MANUAL", EvidenceCollectionMethod.MANUAL),
        ("something-else", EvidenceCollectionMethod.STATIC),
        ("", EvidenceCollectionMethod.STATIC),
    ],
)
def test_the_declared_collection_method_maps_to_its_enum(declared: str, expected: EvidenceCollectionMethod) -> None:
    """`manual` is not `static`: one says a human gathered it, the other that nobody said."""

    assert governance._collection_method({"collection": {"evidence_collection_method": declared}}) is expected


def test_evidence_with_no_collection_block_is_static() -> None:
    assert governance._collection_method({}) is EvidenceCollectionMethod.STATIC


# --------------------------------------------------------------------------- #
# YAML that fails in a way nothing anticipated
# --------------------------------------------------------------------------- #


def test_an_unanticipated_parser_failure_is_still_a_load_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The catch-all exists so a parser bug reaches the operator as exit 2, not a traceback."""

    path = _write(tmp_path, "catalog.yaml", "controls: []\n")

    def _boom(_text: str) -> object:
        raise RuntimeError("the yaml parser gave up")

    monkeypatch.setattr(loader_module.yaml, "safe_load", _boom)

    with pytest.raises(LoadError) as excinfo:
        load_catalog(path)

    assert "catalog.yaml" in str(excinfo.value)
    assert str(tmp_path) not in str(excinfo.value)


def test_a_normal_catalog_still_loads(tmp_path: Path) -> None:
    """The counterpart, and the proof the monkeypatch above was the only thing that broke it."""

    path = _write(tmp_path, "catalog.yaml", "controls:\n  - id: TEST-001\n    title: T\n    assurance: signal\n")
    assert list(load_catalog(path)) == ["TEST-001"]


def test_the_yaml_module_the_loader_uses_is_the_real_one() -> None:
    """Guards the monkeypatch target above from drifting into a no-op."""

    assert loader_module.yaml is yaml
