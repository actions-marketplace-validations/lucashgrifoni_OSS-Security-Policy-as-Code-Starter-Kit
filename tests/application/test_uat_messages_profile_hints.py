"""Regression tests for recommend-profile advice that contradicted the kit's own behaviour."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.application.profile_hints import build_profile_recommendation


def _signal_ids(repo_root: Path) -> set[str]:
    return {s["id"] for s in build_profile_recommendation(repo_root).signals_detected}


def _write_semgrep_evidence(repo_root: Path) -> None:
    ev = repo_root / ".oss-policy-kit" / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "sast-semgrep.json").write_text(
        '{"schema_version": "oss-policy-kit/evidence/sast-semgrep/v1", "status": "ok"}\n',
        encoding="utf-8",
    )


def test_scan_sast_evidence_is_not_reported_as_unrecognized(tmp_path: Path) -> None:
    """Telling an adopter to delete sast-semgrep.json flips SAST-SEMGREP-064 from PASS to UNKNOWN.

    The file is written by the kit's own ``scan-sast`` and read back by ``evaluate``;
    calling it unrecognized and claiming evaluate ignores it is advice that destroys
    working evidence.
    """

    _write_semgrep_evidence(tmp_path)
    assert "evidence_json_unrecognized_filenames" not in _signal_ids(tmp_path)


def test_scan_sast_evidence_does_not_trigger_the_rename_or_remove_note(tmp_path: Path) -> None:
    """The non-bundled-filename note must not fire for a filename the kit itself produces."""

    _write_semgrep_evidence(tmp_path)
    rec = build_profile_recommendation(tmp_path)
    assert not any("non-bundled filenames" in note for note in rec.notes)


def test_python_repo_with_a_sidecar_package_json_is_not_called_a_node_project(tmp_path: Path) -> None:
    """A docs-site package.json must not rebrand a Python repository as Node.js.

    First-match-wins detection returned "Node.js" and short-circuited Python
    detection entirely, so the rationale named the wrong stack and the Python
    signal never reached ``signals_detected`` or ``based_on``.
    """

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "docs-site"}\n', encoding="utf-8")

    rec = build_profile_recommendation(tmp_path)
    ids = {s["id"] for s in rec.signals_detected}
    assert {"python_pyproject", "node_js"} <= ids, "both stack signals must survive detection"

    rationale = rec.suggestions[0]["rationale"]
    assert "Python project" in rationale
    assert "Node.js project" not in rationale
    assert "python_pyproject" in rec.suggestions[0]["based_on"]


def test_sidecar_package_json_does_not_advise_adding_a_yarn_lock(tmp_path: Path) -> None:
    """Lockfile advice belongs to the stack the repository actually is."""

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "docs-site"}\n', encoding="utf-8")

    rec = build_profile_recommendation(tmp_path)
    assert not any("yarn.lock" in note for note in rec.notes)


def test_real_node_repo_still_gets_the_lockfile_note(tmp_path: Path) -> None:
    """Weighting must not silence genuinely useful advice on an actual Node project."""

    (tmp_path / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")

    rec = build_profile_recommendation(tmp_path)
    assert "Node.js project" in rec.suggestions[0]["rationale"]
    assert any("yarn.lock" in note for note in rec.notes)


def test_lockfile_backed_node_outweighs_a_bare_requirements_txt(tmp_path: Path) -> None:
    """A committed lockfile is what proves the tree is installed as Node."""

    (tmp_path / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

    rec = build_profile_recommendation(tmp_path)
    assert "Node.js project" in rec.suggestions[0]["rationale"]
