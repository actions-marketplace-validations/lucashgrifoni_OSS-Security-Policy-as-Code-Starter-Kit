"""The AI controls pass by finding a file, so what counts as finding one is the whole control.

Each of these answers a question about a repository -- does it test for prompt injection, does it
filter model output, does it pin its MCP tool descriptions -- by looking for a file whose name or
contents matches. That makes them the easiest controls in the kit to get wrong in the direction
nobody notices: a pattern that matches nothing marks every repository non-compliant, which reads
as a strict tool, while a pattern that matches too much marks every repository compliant, which
reads as a clean one.

Only the refusals were exercised. Both halves are now asserted, across every pattern each control
recognises, with a near-miss beside each match so the boundary is visible rather than assumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from oss_policy_kit.application.evaluators import ai
from oss_policy_kit.application.evaluators._shared import EvalContext
from oss_policy_kit.domain.models import ControlStatus
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


def _write(root: Path, rel: str, body: str = "") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _mcp_server(root: Path) -> None:
    """The precondition for every MCP control: something declaring an MCP server."""

    _write(root, "mcp.json", json.dumps({"mcpServers": {"kit": {"command": "oss-policy-kit"}}}))


# --------------------------------------------------------------------------- #
# LLM-218A-PW-002 -- adversarial tests anywhere in the tree
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "rel",
    [
        "tests/test_prompt_injection.py",
        "tests/security/test_llm_prompt_injection_corpus.py",
        "test_adversarial.py",
        "tests/test_jailbreak_suite.py",
    ],
)
def test_an_adversarial_test_file_passes_the_control(rel: str, tmp_path: Path) -> None:
    _write(tmp_path, rel, "def test_x() -> None: ...\n")
    outcome = ai.eval_llm_218a_pw_002(_ctx(tmp_path))

    assert outcome.status is ControlStatus.PASS
    assert outcome.evidence_sources


@pytest.mark.parametrize(
    ("label", "rel"),
    [
        ("an ordinary unit test", "tests/test_parser.py"),
        ("the word without the prefix", "tests/prompt_injection.py"),
        ("a fixture, not a test module", "tests/fixtures/adversarial.json"),
    ],
)
def test_a_file_that_is_not_an_adversarial_test_does_not_pass_it(label: str, rel: str, tmp_path: Path) -> None:
    """The counterpart: matching loosely here would pass every repository with a tests directory."""

    _write(tmp_path, rel, "x = 1\n")
    assert ai.eval_llm_218a_pw_002(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# LLM-AI-ACT-002 -- output filtering
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("hint", ai._OUTPUT_FILTER_HINTS)
def test_every_output_filter_hint_is_recognised(hint: str, tmp_path: Path) -> None:
    """Each name is a different vendor or idiom; one that never matched would be dead config."""

    _write(tmp_path, "src/app.py", f"# uses {hint} before returning the completion\n")
    assert ai.eval_llm_ai_act_002(_ctx(tmp_path)).status is ControlStatus.PASS


@pytest.mark.parametrize("ext", ["py", "js", "ts", "mjs"])
def test_the_scan_reaches_every_language_it_claims_to(ext: str, tmp_path: Path) -> None:
    _write(tmp_path, f"src/app.{ext}", "const x = guardrails.check(output)\n")
    assert ai.eval_llm_ai_act_002(_ctx(tmp_path)).status is ControlStatus.PASS


def test_code_with_no_output_filtering_does_not_pass(tmp_path: Path) -> None:
    _write(tmp_path, "src/app.py", "def run(prompt: str) -> str:\n    return llm(prompt)\n")
    assert ai.eval_llm_ai_act_002(_ctx(tmp_path)).status is not ControlStatus.PASS


def test_a_language_the_scan_does_not_read_is_not_searched(tmp_path: Path) -> None:
    """A `.md` mentioning guardrails is documentation, not a filter in the request path."""

    _write(tmp_path, "docs/design.md", "We plan to add guardrails and content_moderation.\n")
    assert ai.eval_llm_ai_act_002(_ctx(tmp_path)).status is not ControlStatus.PASS


# --------------------------------------------------------------------------- #
# AI-AGENT-004 -- test fixtures under tests/
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "rel",
    [
        "tests/test_prompt_injection.py",
        "tests/test_jailbreak.py",
        "tests/test_red_team_cases.py",
        "tests/test_redteam.py",
        "tests/test_adversarial.py",
        "tests/security/anything.txt",
    ],
)
def test_an_agent_security_fixture_passes_the_control(rel: str, tmp_path: Path) -> None:
    """`tests/security/` counts wholesale: a directory named that is the corpus, whatever is in it."""

    _write(tmp_path, rel, "x\n")
    assert ai.eval_ai_agent_004(_ctx(tmp_path)).status is ControlStatus.PASS


def test_a_repository_with_ordinary_tests_only_does_not_pass(tmp_path: Path) -> None:
    _write(tmp_path, "tests/test_parser.py", "def test_x() -> None: ...\n")
    assert ai.eval_ai_agent_004(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --------------------------------------------------------------------------- #
# MCP-TOOL-HASH-001 -- pinned tool descriptions
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("a sha256 field", {"tools": [{"name": "read", "sha256": "a" * 64}]}),
        ("a hash field", {"tools": [{"name": "read", "hash": "sha256:abc"}]}),
        ("the word in a key", {"tool_hashes": {"read": "abc"}}),
    ],
)
def test_pinned_tool_descriptions_pass_the_control(label: str, payload: dict[str, object], tmp_path: Path) -> None:
    _mcp_server(tmp_path)
    _write(tmp_path, ".oss-policy-kit/evidence/mcp-tool-descriptions.json", json.dumps(payload))

    assert ai.eval_mcp_tool_hash_001(_ctx(tmp_path)).status is ControlStatus.PASS, label


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("descriptions with no pin at all", '{"tools": [{"name": "read"}]}'),
        ("a file that does not parse", "{ not json"),
        ("an empty document", "null"),
    ],
)
def test_tool_descriptions_without_a_pin_do_not_pass(label: str, body: str, tmp_path: Path) -> None:
    """Listing the tools is not pinning them; only a recorded digest defends against swapping."""

    _mcp_server(tmp_path)
    _write(tmp_path, ".oss-policy-kit/evidence/mcp-tool-descriptions.json", body)

    assert ai.eval_mcp_tool_hash_001(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED, label


def test_a_repository_with_no_mcp_server_is_not_asked_about_tool_hashes(tmp_path: Path) -> None:
    assert ai.eval_mcp_tool_hash_001(_ctx(tmp_path)).status is ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# MCP-INJECTION-TEST-001
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "rel",
    [
        "tests/test_mcp_injection.py",
        "tests/test_tool_poisoning.py",
        "tests/test_tool-poison_cases.py",
        "test_mcp_prompt_injection.py",
    ],
)
def test_an_mcp_injection_test_passes_the_control(rel: str, tmp_path: Path) -> None:
    _mcp_server(tmp_path)
    _write(tmp_path, rel, "def test_x() -> None: ...\n")

    assert ai.eval_mcp_injection_test_001(_ctx(tmp_path)).status is ControlStatus.PASS


@pytest.mark.parametrize(
    ("label", "rel"),
    [
        ("injection tests that are not about MCP", "tests/test_sql_injection.py"),
        ("MCP tests that are not about injection", "tests/test_mcp_transport.py"),
        ("poisoning without a tool", "tests/test_cache_poisoning.py"),
    ],
)
def test_a_near_miss_does_not_pass_the_injection_control(label: str, rel: str, tmp_path: Path) -> None:
    """Both halves of the name are required, which is what keeps the pass meaningful."""

    _mcp_server(tmp_path)
    _write(tmp_path, rel, "def test_x() -> None: ...\n")

    assert ai.eval_mcp_injection_test_001(_ctx(tmp_path)).status is ControlStatus.MANUAL_REVIEW_REQUIRED, label
