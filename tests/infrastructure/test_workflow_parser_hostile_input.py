"""Workflow parsing on inputs that are hostile, malformed, or simply not what was expected.

`analyze_workflows` reads YAML out of the repository being scanned, so it has to hold two
properties at once: never crash the evaluation on a file it cannot understand, and never
let something it could not parse be mistaken for something it checked and found clean.

The branches doing that work had not been executed, and neither had the `write-all`
classification -- the single broadest permission a job can hold, and one of the findings
this parser exists to produce.

Everything here drives the real `analyze_workflows` over files on disk rather than calling
the private helpers, because the property under test is what the *evaluation* sees.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from oss_policy_kit.infrastructure.workflow_parser import WorkflowAnalysis, analyze_workflows


def _wf(repo: Path, name: str, body: str) -> Path:
    path = repo / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _analyze(repo: Path) -> WorkflowAnalysis:
    return analyze_workflows(repo)


# --------------------------------------------------------------------------- #
# malformed workflows
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("label", "body"),
    [
        ("a bare list", "- not\n- a\n- mapping\n"),
        ("a bare scalar", "just a string\n"),
        ("an empty document", "\n"),
    ],
)
def test_a_workflow_whose_root_is_not_a_mapping_is_recorded_as_a_parse_error(
    tmp_path: Path, label: str, body: str
) -> None:
    """Valid YAML that is not a workflow must be reported, never silently accepted."""

    path = _wf(tmp_path, "broken.yml", body)

    result = _analyze(tmp_path)

    assert [p for p, _reason in result.parse_errors] == [path], label


def test_unparseable_yaml_is_recorded_rather_than_crashing_the_evaluation(tmp_path: Path) -> None:
    """One malformed workflow in a scanned repository must not end the run."""

    path = _wf(tmp_path, "broken.yml", "on: push\njobs:\n  build:\n    steps: [\n")

    result = _analyze(tmp_path)

    assert [p for p, _reason in result.parse_errors] == [path]


def test_a_mutable_action_ref_is_still_found_in_a_workflow_that_would_not_parse(tmp_path: Path) -> None:
    """The text scan is the fallback: a file the YAML parser rejects can still be scanned.

    Losing the finding here is the failure that matters -- an unparseable workflow would
    otherwise look exactly like a clean one to everything downstream.
    """

    path = _wf(tmp_path, "broken.yml", "jobs:\n  build:\n    steps: [\n      - uses: actions/checkout@v4\n")

    result = _analyze(tmp_path)

    assert result.parse_errors
    assert any(p == path for p, _ref in result.mutable_action_refs), "the text fallback found nothing"


def test_a_mutable_ref_is_found_when_the_root_parses_but_is_not_a_mapping(tmp_path: Path) -> None:
    """A separate fallback from the one above, and it had no test.

    Valid YAML whose root is a list never reaches the parsed scan, so only the text scan
    can see it. These are two distinct call sites; a test for the unparseable branch says
    nothing about this one.
    """

    path = _wf(tmp_path, "listy.yml", "- uses: actions/checkout@v4\n- run: echo hi\n")

    result = _analyze(tmp_path)

    assert [p for p, _reason in result.parse_errors] == [path]
    assert any(p == path for p, _ref in result.mutable_action_refs), "the text fallback found nothing"


def test_a_malformed_workflow_is_not_counted_as_having_permissions(tmp_path: Path) -> None:
    """A file that could not be read must not satisfy a control by omission."""

    _wf(tmp_path, "broken.yml", "- not a mapping\n")

    result = _analyze(tmp_path)

    assert result.parse_errors
    assert result.suspicious_permissions == []
    assert result.broad_job_permissions == []


# --------------------------------------------------------------------------- #
# the broadest permissions a workflow can hold
# --------------------------------------------------------------------------- #


def test_write_all_at_the_job_level_is_reported_as_broad(tmp_path: Path) -> None:
    """`write-all` on a job is the single broadest grant; it had never been exercised."""

    path = _wf(
        tmp_path,
        "ci.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    permissions: write-all\n    steps:\n"
        "      - run: echo hi\n",
    )

    result = _analyze(tmp_path)

    assert (path, "build: write-all") in result.broad_job_permissions


@pytest.mark.parametrize("scope", ["contents", "actions", "packages", "deployments"])
def test_a_write_scope_at_the_job_level_is_reported(tmp_path: Path, scope: str) -> None:
    path = _wf(
        tmp_path,
        "ci.yml",
        f"on: push\npermissions:\n  contents: read\njobs:\n  build:\n    permissions:\n      {scope}: write\n"
        "    steps:\n      - run: echo hi\n",
    )

    result = _analyze(tmp_path)

    assert (path, f"build: {scope}=write") in result.broad_job_permissions


def test_a_read_only_job_is_not_reported_as_broad(tmp_path: Path) -> None:
    """The negative case, so the tests above cannot pass by flagging everything."""

    _wf(
        tmp_path,
        "ci.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    permissions:\n      contents: read\n"
        "    steps:\n      - run: echo hi\n",
    )

    assert _analyze(tmp_path).broad_job_permissions == []


@pytest.mark.parametrize("perms", ["write-all", "read-all"])
def test_a_blanket_permission_at_the_workflow_level_is_suspicious(tmp_path: Path, perms: str) -> None:
    path = _wf(tmp_path, "ci.yml", f"on: push\npermissions: {perms}\njobs:\n  build:\n    steps:\n      - run: x\n")

    result = _analyze(tmp_path)

    assert (path, perms) in result.suspicious_permissions


# --------------------------------------------------------------------------- #
# run: given as something other than a string
# --------------------------------------------------------------------------- #


def test_a_run_step_written_as_a_mapping_is_still_scanned(tmp_path: Path) -> None:
    """YAML lets `run:` be a mapping; ignoring that shape would skip its content entirely."""

    _wf(
        tmp_path,
        "ci.yml",
        "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n"
        "      - run:\n          command: semgrep --config auto\n",
    )

    result = _analyze(tmp_path)

    assert result.sast_ci_signals, "a semgrep invocation inside a mapping run: was not seen"


# --------------------------------------------------------------------------- #
# no workflows at all
# --------------------------------------------------------------------------- #


def test_a_repository_with_no_workflows_yields_an_empty_analysis(tmp_path: Path) -> None:
    """Absence has to be distinguishable from "scanned and found nothing wrong"."""

    result = _analyze(tmp_path)

    assert result.workflow_paths == []
    assert result.parse_errors == []
    assert result.suspicious_permissions == []


def test_a_workflows_directory_that_is_a_file_is_not_scanned(tmp_path: Path) -> None:
    """A repository can contain anything; `.github/workflows` need not be a directory."""

    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "workflows").write_text("not a directory\n", encoding="utf-8")

    result = _analyze(tmp_path)

    assert result.workflow_paths == []
    assert result.parse_errors == []
