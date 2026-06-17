"""v10 ASI-depth extension — AGENT-ASI-EXEC-005 / -CASCADE-008 / -ROGUE-010.

These three controls complete the OWASP Top 10 for Agentic Applications (2026,
ASI01-ASI10) coverage of the ``AGENT-ASI-*`` family (ADR-024). ASI03 and ASI04
are intentionally mapped to existing controls (AI-AGENT-008 and
AI-AGENT-010 / MCP-TOOL-HASH-001) rather than duplicated.

Each control is an advisory ``signal``: NOT_APPLICABLE without an agentic
framework, PASS when a clone-side signal is documented, MANUAL_REVIEW_REQUIRED
when the framework is present but the signal is absent. Unit tests mirror
``test_cycle2_controls.py`` (SimpleNamespace contexts, fixtures in tmp_path).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from oss_policy_kit.application.evaluators import (
    EVALUATOR_REGISTRY,
    eval_agent_asi_cascade_008,
    eval_agent_asi_exec_005,
    eval_agent_asi_rogue_010,
)
from oss_policy_kit.application.loader import (
    bundled_kit_root,
    load_catalog,
    load_profile_by_id,
)
from oss_policy_kit.domain.models import ControlStatus

_NEW_ASI_CONTROLS = (
    "AGENT-ASI-EXEC-005",
    "AGENT-ASI-CASCADE-008",
    "AGENT-ASI-ROGUE-010",
)


def _agentic_repo(tmp_path: Path, readme_body: str) -> SimpleNamespace:
    """Build a minimal repo that _agentic_applicable() treats as an AI-agent repo."""
    (tmp_path / "pyproject.toml").write_text("[project]\ndependencies = ['langgraph']\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Agent\n" + readme_body, encoding="utf-8")
    return SimpleNamespace(repo_root=tmp_path)


# A README body that triggers no ASI-depth signal needle (the "vulnerable" fixture).
_NO_SIGNAL_BODY = "This repository ships an autonomous assistant built on a graph framework.\n"


# --- wiring invariants -----------------------------------------------------
def test_new_asi_depth_controls_present_in_catalog_and_registry() -> None:
    catalog = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
    for cid in _NEW_ASI_CONTROLS:
        assert cid in catalog, f"{cid} missing from catalog"
        assert cid in EVALUATOR_REGISTRY, f"{cid} missing from registry"
        assert catalog[cid].lifecycle == "experimental", cid
        assert catalog[cid].assurance == "signal", cid


def test_new_asi_depth_controls_bundled_in_agentic_profile() -> None:
    spec = load_profile_by_id(bundled_kit_root(), "appsec-agentic-asi-1")
    for cid in _NEW_ASI_CONTROLS:
        assert cid in spec.control_ids, f"appsec-agentic-asi-1 should bundle {cid}"


# --- ASI05: code-execution sandboxing -------------------------------------
def test_asi_exec_not_applicable_without_framework(tmp_path: Path) -> None:
    out = eval_agent_asi_exec_005(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_asi_exec_pass_with_sandbox_signal(tmp_path: Path) -> None:
    ctx = _agentic_repo(tmp_path, "We run the code interpreter in a sandboxed execution environment (seccomp).\n")
    out = eval_agent_asi_exec_005(ctx)
    assert out.status is ControlStatus.PASS


def test_asi_exec_manual_when_signal_absent(tmp_path: Path) -> None:
    out = eval_agent_asi_exec_005(_agentic_repo(tmp_path, _NO_SIGNAL_BODY))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- ASI08: cascading-failure guards --------------------------------------
def test_asi_cascade_not_applicable_without_framework(tmp_path: Path) -> None:
    out = eval_agent_asi_cascade_008(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_asi_cascade_pass_with_loop_guard_signal(tmp_path: Path) -> None:
    ctx = _agentic_repo(tmp_path, "The agent loop is bounded with max_iterations and a circuit breaker.\n")
    out = eval_agent_asi_cascade_008(ctx)
    assert out.status is ControlStatus.PASS


def test_asi_cascade_manual_when_signal_absent(tmp_path: Path) -> None:
    out = eval_agent_asi_cascade_008(_agentic_repo(tmp_path, _NO_SIGNAL_BODY))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED


# --- ASI10: rogue-agent inventory / monitoring ----------------------------
def test_asi_rogue_not_applicable_without_framework(tmp_path: Path) -> None:
    out = eval_agent_asi_rogue_010(SimpleNamespace(repo_root=tmp_path))
    assert out.status is ControlStatus.NOT_APPLICABLE


def test_asi_rogue_pass_with_inventory_signal(tmp_path: Path) -> None:
    ctx = _agentic_repo(tmp_path, "We keep an agent registry and monitor for unauthorized agents.\n")
    out = eval_agent_asi_rogue_010(ctx)
    assert out.status is ControlStatus.PASS


def test_asi_rogue_manual_when_signal_absent(tmp_path: Path) -> None:
    out = eval_agent_asi_rogue_010(_agentic_repo(tmp_path, _NO_SIGNAL_BODY))
    assert out.status is ControlStatus.MANUAL_REVIEW_REQUIRED
