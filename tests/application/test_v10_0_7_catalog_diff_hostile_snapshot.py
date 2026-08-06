"""A snapshot is user-supplied input, so a hostile one must not be an internal error.

Found by the v10.0.6 clean-room validation, and it is the same defect the release had
already been cut with: the explicit depth budget lived in some readers and not others, so
`diff-catalogs --from <snapshot>` exited 3 with "maximum recursion depth exceeded" on a
profile.yaml nested 500 levels deep. `--from` points at any directory on disk; nothing
about a snapshot is more trustworthy than a scorecard file.

The old handler also raised `LoadError(f"Could not read profile {profile_file}: ...")`,
which put the absolute path -- and the OS account name -- into the message (M-002).

Both are gone because the reader now routes through the one shared defensive read rather
than catching two exception types and hoping.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from oss_policy_kit.application.catalog_diff import load_snapshot
from oss_policy_kit.application.input_limits import MAX_JSON_DEPTH
from oss_policy_kit.cli.main import app
from oss_policy_kit.domain.errors import LoadError

runner = CliRunner()

_ACCOUNT_MARKER = "SECRET-ACCT-DIR"


def _snapshot(root: Path, profile_body: str) -> Path:
    """A minimal but valid kit data directory, with one profile we control."""

    (root / "controls").mkdir(parents=True, exist_ok=True)
    (root / "controls" / "catalog.yaml").write_text(
        "schema_version: oss-policy-kit/catalog/v1\ncontrols:\n"
        "  - id: GOV-SEC-001\n"
        "    title: Security policy present\n"
        "    category: governance\n"
        "    severity: high\n",
        encoding="utf-8",
    )
    prof = root / "profiles" / "p1"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "profile.yaml").write_text(profile_body, encoding="utf-8")
    return root


def test_healthy_snapshot_still_loads(tmp_path: Path) -> None:
    """The guard must not cost the ordinary case: a real snapshot still parses."""

    snap = _snapshot(tmp_path / "snap", "id: p1\ntitle: P1\ncontrols:\n  - GOV-SEC-001\n")

    loaded = load_snapshot(snap, label="--from")

    assert loaded.profiles["p1"] == ("GOV-SEC-001",)


def test_deeply_nested_profile_is_a_load_error_not_a_crash(tmp_path: Path) -> None:
    """Refused by the explicit budget, at a depth no interpreter would choke on.

    Deliberately just past the budget rather than deep enough to exhaust the stack: a
    3000-level fixture would pass even with the budget removed, because CPython's C
    stack raises on Windows and not on Linux. That asymmetry is what put this class of
    defect into a shipped release twice.
    """

    depth = MAX_JSON_DEPTH + 20
    body = "id: p1\ntitle: P1\ncontrols: " + "[" * depth + "]" * depth + "\n"
    snap = _snapshot(tmp_path / "snap", body)

    with pytest.raises(LoadError) as excinfo:
        load_snapshot(snap, label="--from")

    message = str(excinfo.value)
    assert "nested too deeply" in message
    assert str(MAX_JSON_DEPTH) in message


def test_malformed_profile_error_names_the_file_but_not_its_directory(tmp_path: Path) -> None:
    """M-002: the message identifies what to fix without mapping the author's disk."""

    root = tmp_path / _ACCOUNT_MARKER / "snap"
    snap = _snapshot(root, "id: p1\ncontrols: [unclosed\n")

    with pytest.raises(LoadError) as excinfo:
        load_snapshot(snap, label="--from")

    message = str(excinfo.value)
    assert "profile.yaml" in message, "the message must still say which file to fix"
    assert _ACCOUNT_MARKER not in message, "the snapshot's directory chain leaked"
    assert str(snap) not in message


def test_cli_reports_a_hostile_snapshot_as_a_usage_error(tmp_path: Path) -> None:
    """End to end: exit 2, no traceback, and no `Unexpected error` wording."""

    depth = MAX_JSON_DEPTH + 20
    body = "id: p1\ntitle: P1\ncontrols: " + "[" * depth + "]" * depth + "\n"
    good = _snapshot(tmp_path / "good", "id: p1\ntitle: P1\ncontrols:\n  - GOV-SEC-001\n")
    bad = _snapshot(tmp_path / _ACCOUNT_MARKER / "bad", body)

    result = runner.invoke(app, ["diff-catalogs", "--from", str(good), "--to", str(bad)])

    assert result.exit_code == 2, f"exit={result.exit_code}\n{result.output}"
    assert "Traceback" not in result.output
    assert "Unexpected error" not in result.output
    assert _ACCOUNT_MARKER not in result.output
