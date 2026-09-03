"""Reading ``owner/repo`` out of ``.git/config``, and refusing to guess when it is not GitHub.

This slug decides which repository the GitHub collector queries. Getting it wrong is not a
crash -- it is a collection against somebody else's repository, or against nothing, reported as
if it were this one. So the parser has to be exact about three things: only the ``origin``
remote counts, only github.com hosts count, and anything it cannot read yields ``None`` rather
than a partial guess.

Every URL form git actually writes is here (HTTPS, SSH shorthand, ``ssh://``, with and without
``.git``, with a query string), each paired with a near-miss that must not parse: a GitLab
remote, a host that merely contains "github.com" as a prefix of something else, an owner with
no repository.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.git_remote import (
    _github_slug_from_url,
    _parse_origin_github_slug,
    read_github_repo_slug_from_git_config,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/acme/widget",
        "https://github.com/acme/widget.git",
        "http://github.com/acme/widget.git",
        "https://github.com/acme/widget/",
        "https://github.com/acme/widget.git?foo=bar",
        "git@github.com:acme/widget.git",
        "git@github.com:acme/widget",
        "ssh://git@github.com/acme/widget.git",
    ],
)
def test_every_url_form_git_writes_yields_the_same_slug(url: str) -> None:
    assert _github_slug_from_url(url) == "acme/widget"


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/acme/widget.git",
        "git@gitlab.com:acme/widget.git",
        "https://github.company.com/acme/widget.git",
        "https://github.com/acme",
        "git@github.com:acme",
        "",
        "not-a-url",
    ],
)
def test_a_remote_that_is_not_a_github_repository_yields_nothing(url: str) -> None:
    """A partial guess here would point the collector at the wrong repository."""

    assert _github_slug_from_url(url) is None


# --------------------------------------------------------------------------- #
# Walking .git/config
# --------------------------------------------------------------------------- #


def test_only_the_origin_remote_is_read() -> None:
    """An upstream fork remote must not be mistaken for the repository being evaluated."""

    config = (
        '[remote "upstream"]\n'
        "\turl = https://github.com/upstream-org/widget.git\n"
        '[remote "origin"]\n'
        "\turl = https://github.com/acme/widget.git\n"
    )
    assert _parse_origin_github_slug(config) == "acme/widget"


def test_a_config_whose_origin_is_not_github_yields_nothing() -> None:
    config = '[remote "origin"]\n\turl = https://gitlab.com/acme/widget.git\n'
    assert _parse_origin_github_slug(config) is None


def test_lines_outside_a_remote_section_are_ignored() -> None:
    """`url =` appears under other sections too; only the one inside origin counts."""

    config = (
        "[core]\n\turl = https://github.com/decoy/decoy.git\n"
        '[remote "origin"]\n\turl = git@github.com:acme/widget.git\n'
    )
    assert _parse_origin_github_slug(config) == "acme/widget"


def test_a_section_header_is_matched_case_insensitively() -> None:
    config = '[REMOTE "ORIGIN"]\n\tURL = https://github.com/acme/widget.git\n'
    assert _parse_origin_github_slug(config) == "acme/widget"


def test_an_origin_section_without_a_url_yields_nothing() -> None:
    config = '[remote "origin"]\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
    assert _parse_origin_github_slug(config) is None


def test_a_quoted_url_value_is_unquoted() -> None:
    config = '[remote "origin"]\n\turl = "https://github.com/acme/widget.git"\n'
    assert _parse_origin_github_slug(config) == "acme/widget"


# --------------------------------------------------------------------------- #
# Reading from disk
# --------------------------------------------------------------------------- #


def test_a_repository_without_a_git_config_yields_nothing(tmp_path: Path) -> None:
    """An exported tarball or a fresh directory has no config; that is not an error."""

    assert read_github_repo_slug_from_git_config(tmp_path) is None


def test_the_slug_is_read_from_a_real_git_config(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text('[remote "origin"]\n\turl = https://github.com/acme/widget.git\n', encoding="utf-8")
    assert read_github_repo_slug_from_git_config(tmp_path) == "acme/widget"


def test_a_config_with_undecodable_bytes_is_still_read(tmp_path: Path) -> None:
    """`errors="replace"` is deliberate: a stray byte must not hide a readable origin."""

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_bytes(b'[remote "origin"]\n\turl = https://github.com/acme/widget.git\n\t# \xff\xfe\n')
    assert read_github_repo_slug_from_git_config(tmp_path) == "acme/widget"


@pytest.mark.parametrize(
    "line",
    ["\turl\n", "\turlPrefix = https://github.com/decoy/decoy.git\n"],
    ids=["url-with-no-value", "a-different-key-starting-with-url"],
)
def test_a_key_that_only_looks_like_url_is_skipped(line: str) -> None:
    """`urlPrefix` and a valueless `url` both start with "url" and neither is the remote URL."""

    config = f'[remote "origin"]\n{line}\turl = https://github.com/acme/widget.git\n'
    assert _parse_origin_github_slug(config) == "acme/widget"


def test_an_origin_whose_only_url_like_key_is_not_a_url_yields_nothing() -> None:
    config = '[remote "origin"]\n\turlPrefix = https://github.com/decoy/decoy.git\n'
    assert _parse_origin_github_slug(config) is None
