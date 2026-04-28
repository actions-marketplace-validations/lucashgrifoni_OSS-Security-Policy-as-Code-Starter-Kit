"""GH-WF-018: reusable workflow secrets inherit — structural YAML detection."""

from __future__ import annotations

from pathlib import Path

from oss_policy_kit.infrastructure.workflow_parser import analyze_workflows


def _write_workflow(tmp_path: Path, content: str) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "ci.yml").write_text(content, encoding="utf-8")


def test_gh_wf018_detects_secrets_inherit_structural(tmp_path: Path) -> None:
    """Reusable workflow call with secrets: inherit is flagged."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
jobs:
  call-ci:
    uses: org/repo/.github/workflows/ci.yml@main
    secrets: inherit
""",
    )
    wf = analyze_workflows(tmp_path)
    assert wf.reusable_secrets_inherit_paths, "expected secrets:inherit to be detected"


def test_gh_wf018_not_detected_when_no_secrets_key(tmp_path: Path) -> None:
    """Reusable workflow call without secrets key is not flagged."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
jobs:
  call-ci:
    uses: org/repo/.github/workflows/ci.yml@main
""",
    )
    wf = analyze_workflows(tmp_path)
    assert not wf.reusable_secrets_inherit_paths


def test_gh_wf018_not_detected_when_secrets_inherit_in_comment_only(tmp_path: Path) -> None:
    """secrets: inherit in a YAML comment must NOT be flagged — this proves the structural upgrade."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
# secrets: inherit — this is a documentation note, not a real key
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
""",
    )
    wf = analyze_workflows(tmp_path)
    assert not wf.reusable_secrets_inherit_paths, "secrets: inherit in YAML comment must not trigger detection"


def test_gh_wf018_not_detected_without_reusable_call(tmp_path: Path) -> None:
    """Normal workflow without any reusable call is not flagged."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo build
""",
    )
    wf = analyze_workflows(tmp_path)
    assert not wf.reusable_secrets_inherit_paths


def test_gh_wf018_not_detected_with_explicit_secrets_mapping(tmp_path: Path) -> None:
    """Reusable call with explicit secrets mapping (not 'inherit') is not flagged."""
    _write_workflow(
        tmp_path,
        """\
on: push
permissions:
  contents: read
jobs:
  call-ci:
    uses: org/repo/.github/workflows/ci.yml@main
    secrets:
      MY_SECRET: ${{ secrets.MY_SECRET }}
""",
    )
    wf = analyze_workflows(tmp_path)
    assert not wf.reusable_secrets_inherit_paths
