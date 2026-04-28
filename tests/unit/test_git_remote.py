"""Tests for parsing GitHub slug from ``.git/config``."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.git_remote import read_github_repo_slug_from_git_config


def test_read_slug_from_https_origin(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/octo-org/hello-world.git\n',
        encoding="utf-8",
    )
    assert read_github_repo_slug_from_git_config(tmp_path) == "octo-org/hello-world"


def test_read_slug_from_ssh_origin(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        '[remote "origin"]\n\turl = git@github.com:acme/widget.git\n',
        encoding="utf-8",
    )
    assert read_github_repo_slug_from_git_config(tmp_path) == "acme/widget"
