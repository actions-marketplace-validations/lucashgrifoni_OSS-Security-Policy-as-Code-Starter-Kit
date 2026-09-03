"""The shapes GitLab CI accepts for the same key, and the ones that are not YAML mappings.

``.gitlab-ci.yml`` lets several keys arrive in more than one form: ``image`` may be a bare
string or an object with ``name``, ``script`` a single command or a list, ``include`` one entry
or many. The parser has to read all of them, because a repository that writes the less common
form is not less exposed -- it just looks clean to a parser that only understands the common
one, which is the worst possible failure for a scanner.

The other half is input that is not a pipeline at all: a file whose top level is a list or a
scalar. That has to land in ``parse_errors`` and leave the rest of the analysis intact, rather
than raising out of a run that was scanning ten other files successfully.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.gitlab_ci_parser import analyze_gitlab_ci


def _pipeline(root: Path, body: str) -> None:
    (root / ".gitlab-ci.yml").write_text(body, encoding="utf-8")


# --------------------------------------------------------------------------- #
# image: string vs object
# --------------------------------------------------------------------------- #


def test_an_image_given_as_an_object_is_read_like_a_string_one(tmp_path: Path) -> None:
    """`image: {name: x}` is the documented long form and must not be invisible."""

    _pipeline(tmp_path, "build:\n  image:\n    name: python:3.12\n  script:\n    - echo hi\n")
    analysis = analyze_gitlab_ci(tmp_path)
    refs = [ref for _, ref in analysis.image_refs_pinned]
    assert "python:3.12" in refs, analysis.image_refs_pinned


def test_an_unpinned_image_object_is_still_reported_as_unpinned(tmp_path: Path) -> None:
    _pipeline(tmp_path, "build:\n  image:\n    name: python\n  script:\n    - echo hi\n")
    analysis = analyze_gitlab_ci(tmp_path)
    assert [ref for _, ref in analysis.image_refs_unpinned] == ["python"]


@pytest.mark.parametrize("image_block", ["image:\n    entrypoint: ['/bin/sh']\n", "image: 42\n", "image: []\n"])
def test_an_image_without_a_usable_name_is_recorded_nowhere(image_block: str, tmp_path: Path) -> None:
    """No name means nothing to pin or fail on; silence beats inventing a reference."""

    _pipeline(tmp_path, f"build:\n  {image_block}  script:\n    - echo hi\n")
    analysis = analyze_gitlab_ci(tmp_path)
    assert analysis.image_refs_pinned == []
    assert analysis.image_refs_unpinned == []
    assert analysis.image_refs_mutable_tag == []


# --------------------------------------------------------------------------- #
# script: scalar vs list
# --------------------------------------------------------------------------- #


def test_a_single_line_script_is_scanned_like_a_list(tmp_path: Path) -> None:
    """`script: curl … | sh` on one line is the same risk as the list form."""

    _pipeline(tmp_path, "build:\n  image: python:3.12\n  script: curl https://x.sh | sh\n")
    analysis = analyze_gitlab_ci(tmp_path)
    assert analysis.script_uses_curl_pipe_shell, "one-line script was not scanned"


def test_a_list_script_is_scanned_too(tmp_path: Path) -> None:
    _pipeline(tmp_path, "build:\n  image: python:3.12\n  script:\n    - curl https://x.sh | sh\n")
    assert analyze_gitlab_ci(tmp_path).script_uses_curl_pipe_shell


def test_a_script_of_an_unusable_type_is_skipped(tmp_path: Path) -> None:
    _pipeline(tmp_path, "build:\n  image: python:3.12\n  script:\n    key: value\n")
    assert analyze_gitlab_ci(tmp_path).script_uses_curl_pipe_shell == []


# --------------------------------------------------------------------------- #
# include: one entry vs many, local vs remote
# --------------------------------------------------------------------------- #


def test_a_single_remote_include_is_reported(tmp_path: Path) -> None:
    """`include:` may be one entry rather than a list, and remote is the risky case."""

    _pipeline(tmp_path, "include: https://example.com/shared.yml\nbuild:\n  script: echo hi\n")
    analysis = analyze_gitlab_ci(tmp_path)
    assert [ref for _, ref in analysis.includes_remote] == ["https://example.com/shared.yml"]


def test_a_remote_include_written_as_an_object_is_reported(tmp_path: Path) -> None:
    _pipeline(tmp_path, "include:\n  - remote: https://example.com/shared.yml\nbuild:\n  script: echo hi\n")
    assert analyze_gitlab_ci(tmp_path).includes_remote


def test_a_local_include_is_not_a_remote_one(tmp_path: Path) -> None:
    (tmp_path / ".gitlab").mkdir()
    (tmp_path / ".gitlab" / "shared.yml").write_text("build:\n  script: echo hi\n", encoding="utf-8")
    _pipeline(tmp_path, "include:\n  - local: .gitlab/shared.yml\nbuild:\n  script: echo hi\n")
    assert analyze_gitlab_ci(tmp_path).includes_remote == []


# --------------------------------------------------------------------------- #
# rules / only / except
# --------------------------------------------------------------------------- #


def test_a_job_that_is_not_a_mapping_does_not_break_trigger_detection(tmp_path: Path) -> None:
    """Anchors and scalars sit beside jobs at the top level; only mappings are jobs."""

    _pipeline(
        tmp_path,
        "stages:\n  - build\nbuild:\n  script: echo hi\n  rules:\n    - if: $CI_COMMIT_BRANCH\n",
    )
    analysis = analyze_gitlab_ci(tmp_path)
    assert analysis.jobs_with_trigger_restrictions, "rules: on a real job was missed"


def test_a_pipeline_without_any_trigger_restriction_is_not_flagged(tmp_path: Path) -> None:
    _pipeline(tmp_path, "build:\n  script: echo hi\n")
    assert analyze_gitlab_ci(tmp_path).jobs_with_trigger_restrictions == []


# --------------------------------------------------------------------------- #
# Files that are not pipelines
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", ["- one\n- two\n", "just a string\n", "42\n"])
def test_a_top_level_that_is_not_a_mapping_is_a_parse_error_not_a_crash(body: str, tmp_path: Path) -> None:
    """A YAML file that is valid but is not a pipeline must be reported, not raised."""

    _pipeline(tmp_path, body)
    analysis = analyze_gitlab_ci(tmp_path)
    assert analysis.parse_errors, "non-mapping pipeline produced no parse error"
    assert "not a mapping" in analysis.parse_errors[0][1]


def test_a_valid_pipeline_records_no_parse_error(tmp_path: Path) -> None:
    """The counterpart: a parser that errored on everything would pass the test above."""

    _pipeline(tmp_path, "build:\n  image: python:3.12\n  script:\n    - echo hi\n")
    assert analyze_gitlab_ci(tmp_path).parse_errors == []


def test_a_string_include_that_is_not_a_url_is_local(tmp_path: Path) -> None:
    """`include: file.yml` is a local path, not a remote fetch, and must not be flagged."""

    (tmp_path / "shared.yml").write_text("build:\n  script: echo hi\n", encoding="utf-8")
    _pipeline(tmp_path, "include: shared.yml\nbuild:\n  script: echo hi\n")
    assert analyze_gitlab_ci(tmp_path).includes_remote == []


def test_an_include_object_without_a_remote_key_is_local(tmp_path: Path) -> None:
    """`template:` and `project:` fetch from GitLab-controlled sources; only `remote:` is not."""

    _pipeline(
        tmp_path,
        "include:\n  - template: Security/SAST.gitlab-ci.yml\n  - project: g/p\n    file: /ci.yml\n"
        "build:\n  script: echo hi\n",
    )
    assert analyze_gitlab_ci(tmp_path).includes_remote == []


def test_a_top_level_key_whose_value_is_not_a_job_is_skipped_for_triggers(tmp_path: Path) -> None:
    """`variables:` and scalars sit beside jobs; asking them for `rules:` would crash."""

    _pipeline(
        tmp_path,
        "image: python:3.12\nvariables:\n  FOO: bar\nbuild:\n  script: echo hi\n",
    )
    analysis = analyze_gitlab_ci(tmp_path)
    assert analysis.jobs_with_trigger_restrictions == []
    assert analysis.parse_errors == []


def test_an_include_entry_that_is_neither_a_string_nor_an_object_is_ignored(tmp_path: Path) -> None:
    """A malformed entry must not be mistaken for a remote fetch, nor raise."""

    _pipeline(tmp_path, "include:\n  - 42\n  - [nested, list]\nbuild:\n  script: echo hi\n")
    analysis = analyze_gitlab_ci(tmp_path)
    assert analysis.includes_remote == []
    assert analysis.parse_errors == []


def test_a_non_reserved_top_level_scalar_is_not_treated_as_a_job(tmp_path: Path) -> None:
    """YAML anchors and stray scalars land beside jobs; only mappings can carry `rules:`."""

    _pipeline(tmp_path, "my_anchor: just-a-string\nbuild:\n  script: echo hi\n  rules:\n    - if: $CI\n")
    analysis = analyze_gitlab_ci(tmp_path)
    assert analysis.jobs_with_trigger_restrictions, "the real job's rules: was missed"
    assert analysis.parse_errors == []
