"""ADR-028 PR2: declared applicability preconditions + opt-in applicability engine.

Covers the catalog metadata parsing/validation, the filesystem resolver, and the
engine short-circuit — including the safety property that for the bundled pilot
controls (CONT-IMAGE-*), enabling the engine produces the *same* result as today
(their evaluator already returned NOT_APPLICABLE without a Dockerfile).
"""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from tests.conftest import ROOT
from typer.testing import CliRunner

from oss_policy_kit.application.applicability import resolve_applicability
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.loader import (
    ApplicabilitySpec,
    ProfileSpec,
    _parse_applicability,
    bundled_kit_root,
    load_catalog,
)
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import LoadError
from oss_policy_kit.domain.models import ControlStatus

runner = CliRunner()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_CATALOG = load_catalog(bundled_kit_root() / "controls" / "catalog.yaml")
_CONT = ("CONT-IMAGE-001", "CONT-IMAGE-002", "CONT-IMAGE-003")


def _profile(*control_ids: str) -> ProfileSpec:
    return ProfileSpec(id="t-applic", title="t", description="d", audience="a", control_ids=tuple(control_ids))


def _statuses(repo: Path, control_ids: tuple[str, ...], *, engine: bool) -> dict[str, ControlStatus]:
    report = evaluate_repository(
        repo_root=repo,
        profile=_profile(*control_ids),
        catalog=_CATALOG,
        waiver_outcome=None,
        scorecard=None,
        applicability_engine=engine,
    )
    return {r.control_id: r.status for r in report.results}


# --------------------------------------------------------------------------- #
# loader: parse + validate
# --------------------------------------------------------------------------- #


def test_bundled_catalog_pilot_has_applicability() -> None:
    spec = _CATALOG["CONT-IMAGE-001"].applicability
    assert spec is not None
    assert any("Dockerfile" in p for p in spec.requires_any_files)


def test_parse_applicability_none_and_valid() -> None:
    assert _parse_applicability("X", None) is None
    spec = _parse_applicability("X", {"requires_any_files": ["**/Dockerfile", "  "]})
    assert spec == ApplicabilitySpec(requires_any_files=("**/Dockerfile",))


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-dict",
        {"requires_any_files": "not-a-list"},
        {"requires_any_files": []},
        {"requires_any_files": ["  "]},
        {"requires_files": ["**/Dockerfile"]},  # unknown key -> fail-closed
    ],
)
def test_parse_applicability_rejects_malformed(raw: object) -> None:
    with pytest.raises(LoadError):
        _parse_applicability("X", raw)


# --------------------------------------------------------------------------- #
# resolver
# --------------------------------------------------------------------------- #


def test_resolve_applicability_no_spec_is_always_applicable(tmp_path: Path) -> None:
    assert resolve_applicability(None, tmp_path) == (True, None)
    assert resolve_applicability(ApplicabilitySpec(), tmp_path) == (True, None)


def test_resolve_applicability_match_and_no_match(tmp_path: Path) -> None:
    spec = ApplicabilitySpec(requires_any_files=("**/Dockerfile",))
    applicable, reason = resolve_applicability(spec, tmp_path)
    assert applicable is False and reason is not None and "Precondition not met" in reason

    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    assert resolve_applicability(spec, tmp_path) == (True, None)


def test_resolve_applicability_matches_nested_dockerfile(tmp_path: Path) -> None:
    sub = tmp_path / "services" / "api"
    sub.mkdir(parents=True)
    (sub / "app.Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    assert resolve_applicability(ApplicabilitySpec(requires_any_files=("**/*.Dockerfile",)), tmp_path)[0] is True


# --------------------------------------------------------------------------- #
# engine: safety property (engine on == off for the pilot) + real short-circuit
# --------------------------------------------------------------------------- #


def test_pilot_no_dockerfile_engine_on_equals_off(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# repo\n", encoding="utf-8")
    off = _statuses(tmp_path, _CONT, engine=False)
    on = _statuses(tmp_path, _CONT, engine=True)
    assert off == on
    assert all(s == ControlStatus.NOT_APPLICABLE for s in on.values())


def test_pilot_with_dockerfile_engine_on_equals_off(tmp_path: Path) -> None:
    # Unpinned FROM -> CONT-IMAGE-001 FAIL; precondition met so the engine must run the evaluator.
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:22.04\nUSER app\n", encoding="utf-8")
    off = _statuses(tmp_path, _CONT, engine=False)
    on = _statuses(tmp_path, _CONT, engine=True)
    assert off == on
    assert on["CONT-IMAGE-001"] == ControlStatus.FAIL  # evaluator actually ran


def test_engine_short_circuits_a_control_that_would_otherwise_pass(tmp_path: Path) -> None:
    # GOV-LIC-004 passes when a LICENSE exists; give it a precondition that cannot be met
    # and confirm the engine forces NOT_APPLICABLE *without* running the evaluator.
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    catalog = dict(_CATALOG)
    catalog["GOV-LIC-004"] = dataclasses.replace(
        catalog["GOV-LIC-004"], applicability=ApplicabilitySpec(requires_any_files=("**/__never_exists__",))
    )
    common = dict(
        repo_root=tmp_path, profile=_profile("GOV-LIC-004"), catalog=catalog, waiver_outcome=None, scorecard=None
    )
    off = {r.control_id: r.status for r in evaluate_repository(**common, applicability_engine=False).results}
    on = {r.control_id: r.status for r in evaluate_repository(**common, applicability_engine=True).results}
    assert off["GOV-LIC-004"] == ControlStatus.PASS
    assert on["GOV-LIC-004"] == ControlStatus.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# CLI flag is wired (both default off and explicit on)
# --------------------------------------------------------------------------- #


def test_cli_applicability_engine_flag(tmp_path: Path) -> None:
    from tests.conftest import EXAMPLE_HARDENED

    res = runner.invoke(
        app,
        [
            "evaluate",
            "--target",
            str(EXAMPLE_HARDENED),
            "--profile",
            "github-level-1",
            "--applicability-engine",
            "--format",
            "json",
            "--summary-only",
            "--output-dir",
            str(tmp_path / "o"),
        ],
    )
    assert res.exit_code == 0, res.output


def test_cli_help_lists_applicability_flag() -> None:
    # Run in a real subprocess with a deterministic wide terminal. In-process
    # CliRunner does not reliably propagate COLUMNS to Rich under CI, so Rich
    # truncates the long option name (`--applicability-e…`) and the test flakes.
    # A subprocess honors COLUMNS; we strip ANSI and collapse all whitespace so
    # the substring assertion survives any wrap/render difference.
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "200"
    env["LINES"] = "40"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", "evaluate", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    no_ansi = _ANSI_RE.sub("", proc.stdout + proc.stderr)
    assert "--applicability-engine" in "".join(no_ansi.split()), no_ansi
