"""Deterministic branch coverage for ``emit-insights`` helpers and validate path.

``test_emit_insights_branches.py`` covers the happy paths but leaves the
``_git_remote_url`` subprocess branches, ``_security_md_email`` guards, the
header-shape validation branch, and the ``--validate`` failure exit
environment-dependent. These tests monkeypatch ``subprocess.run`` and the
validator so every branch is hit regardless of whether ``git`` is on PATH.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import emit_insights as ei
from oss_policy_kit.cli.main import app

runner = CliRunner()


def _fake_run(returncode: int, stdout: str):
    def _run(*a: object, **k: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=returncode, stdout=stdout)

    return _run


# --------------------------------------------------------------------------- #
# _git_remote_url
# --------------------------------------------------------------------------- #


def test_git_remote_url_subprocess_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise OSError("git not found")

    monkeypatch.setattr(ei.subprocess, "run", _boom)
    assert ei._git_remote_url(tmp_path) is None


def test_git_remote_url_nonzero_returncode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ei.subprocess, "run", _fake_run(128, ""))
    assert ei._git_remote_url(tmp_path) is None


def test_git_remote_url_empty_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ei.subprocess, "run", _fake_run(0, "   \n"))
    assert ei._git_remote_url(tmp_path) is None


def test_git_remote_url_ssh_normalised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ei.subprocess, "run", _fake_run(0, "git@github.com:org/repo.git\n"))
    assert ei._git_remote_url(tmp_path) == "https://github.com/org/repo"


def test_git_remote_url_https_dot_git_stripped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ei.subprocess, "run", _fake_run(0, "https://github.com/org/repo.git\n"))
    assert ei._git_remote_url(tmp_path) == "https://github.com/org/repo"


def test_git_remote_url_plain_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ei.subprocess, "run", _fake_run(0, "https://example.com/x/y\n"))
    assert ei._git_remote_url(tmp_path) == "https://example.com/x/y"


# --------------------------------------------------------------------------- #
# _security_md_email
# --------------------------------------------------------------------------- #


def test_security_md_email_none() -> None:
    assert ei._security_md_email(None) is None


def test_security_md_email_found(tmp_path: Path) -> None:
    p = tmp_path / "SECURITY.md"
    p.write_text("Contact: appsec@example.org for reports.\n", encoding="utf-8")
    assert ei._security_md_email(p) == "appsec@example.org"


def test_security_md_email_no_match(tmp_path: Path) -> None:
    p = tmp_path / "SECURITY.md"
    p.write_text("No address here.\n", encoding="utf-8")
    assert ei._security_md_email(p) is None


def test_security_md_email_oserror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "SECURITY.md"
    p.write_text("appsec@example.org\n", encoding="utf-8")

    def _boom(self: Path, *a: object, **k: object) -> str:
        raise OSError("unreadable")

    monkeypatch.setattr(Path, "read_text", _boom)
    assert ei._security_md_email(p) is None


# --------------------------------------------------------------------------- #
# _validate_insights_structure
# --------------------------------------------------------------------------- #


def test_validate_insights_header_not_a_dict() -> None:
    errs = ei._validate_insights_structure({"header": "nope", "project-lifecycle": {"status": "active"}})
    assert errs == ["header must be an object"]


def test_validate_insights_missing_fields_and_bad_schema_version() -> None:
    errs = ei._validate_insights_structure(
        {"header": {"schema-version": "9.9.9"}, "project-lifecycle": {"no-status": True}}
    )
    assert any("header.last-updated missing" in e for e in errs)
    assert any("schema-version must be" in e for e in errs)
    assert any("project-lifecycle.status missing" in e for e in errs)


def test_validate_insights_missing_top_level() -> None:
    errs = ei._validate_insights_structure({})
    assert any("top-level field missing: header" in e for e in errs)
    assert any("project-lifecycle" in e for e in errs)


# --------------------------------------------------------------------------- #
# _build_insights_document — remote/contributing/codeowners/dependabot branches
# --------------------------------------------------------------------------- #


def test_build_insights_document_full(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "SECURITY.md").write_text("Report to security@example.org\n", encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @org/maintainers\n", encoding="utf-8")
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "dependabot.yml").write_text("version: 2\n", encoding="utf-8")

    monkeypatch.setattr(ei, "_git_remote_url", lambda root: "https://github.com/org/repo")
    doc = ei._build_insights_document(tmp_path)

    assert doc["header"]["url"] == "https://github.com/org/repo"
    assert doc["contribution-policy"]["contributing-policy"].startswith("https://github.com/org/repo/blob/main/")
    assert doc["project-administrators"][0]["affiliation"] == "CODEOWNERS"
    assert doc["vulnerability-reporting"]["email-contact"] == "security@example.org"
    assert doc["security-contacts"][0] == {"type": "email", "value": "security@example.org"}
    assert "dependencies" in doc


def test_build_insights_document_no_remote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "SECURITY.md").write_text("no email in here\n", encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\n", encoding="utf-8")
    monkeypatch.setattr(ei, "_git_remote_url", lambda root: None)
    doc = ei._build_insights_document(tmp_path)

    assert "url" not in doc["header"]
    # relative path used when no remote URL is available
    assert doc["contribution-policy"]["contributing-policy"] == "CONTRIBUTING.md"
    assert doc["vulnerability-reporting"]["security-policy"] == "SECURITY.md"
    # no email found -> no email-contact and no security-contacts
    assert "email-contact" not in doc["vulnerability-reporting"]
    assert "security-contacts" not in doc


# --------------------------------------------------------------------------- #
# emit-insights command --validate failure (exit 1)
# --------------------------------------------------------------------------- #


def test_emit_insights_validate_failure_exit_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ei, "_validate_insights_structure", lambda doc: ["forced validation error"])
    out = tmp_path / "insights.yml"
    res = runner.invoke(app, ["emit-insights", "--target", str(tmp_path), "--output", str(out), "--validate"])
    assert res.exit_code == 1
    assert "validation error" in res.output
    assert not out.exists()  # write is skipped when validation fails
