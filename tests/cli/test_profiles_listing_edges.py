"""What `profiles` counts, what it prints on a terminal, and how it fails.

The assurance mix is the number an adopter uses to judge a profile before adopting it: how much
of this ladder is checked deterministically, how much rests on a keyword signal, and how much
needs evidence they have to produce. Miscounting any of the three misrepresents the profile, so
all three classes are asserted against the real bundled catalog rather than a fixture -- a
fixture would keep passing after the catalog changed underneath it.

The interactive rendering is the other half. On a terminal the compact view prints a panel and
stops, pointing at the fuller views; the grid is for pipes and files. Getting that backwards
either floods a terminal or hands a script a box-drawn panel it cannot parse.
"""

from __future__ import annotations

import json

import pytest
import typer
from typer.testing import CliRunner

from oss_policy_kit.application.loader import load_catalog, load_profile_by_id, merge_kit_root
from oss_policy_kit.cli import profiles as pr
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.main import app

runner = CliRunner()


# --------------------------------------------------------------------------- #
# The assurance mix
# --------------------------------------------------------------------------- #


def _mix(profile_id: str) -> dict[str, int]:
    root = merge_kit_root(None)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    return pr._profile_assurance_mix(tuple(load_profile_by_id(root, profile_id).control_ids), catalog)


@pytest.mark.parametrize("profile_id", ["github-level-3", "aws-level-3"])
def test_every_assurance_class_is_counted(profile_id: str) -> None:
    """A hardening ladder draws on all three; a zero in any of them would be a miscount."""

    mix = _mix(profile_id)

    assert mix["deterministic"] > 0
    assert mix["signal"] > 0
    assert mix["evidence-backed"] > 0


def test_the_counts_add_up_to_the_profiles_controls() -> None:
    """Nothing silently uncounted: every control lands in exactly one class."""

    root = merge_kit_root(None)
    profile = load_profile_by_id(root, "github-level-3")
    mix = _mix("github-level-3")

    assert mix["deterministic"] + mix["signal"] + mix["evidence-backed"] == len(profile.control_ids)


def test_a_control_the_catalog_does_not_know_is_skipped_rather_than_miscounted() -> None:
    """A profile naming a control this build does not ship must not inflate any class."""

    root = merge_kit_root(None)
    catalog = load_catalog(root / "controls" / "catalog.yaml")

    assert pr._profile_assurance_mix(("NO-SUCH-CONTROL-999",), catalog) == {
        "deterministic": 0,
        "signal": 0,
        "evidence-backed": 0,
        "det": 0,
        "sig": 0,
        "evi": 0,
    }


# --------------------------------------------------------------------------- #
# Rendering on a terminal
# --------------------------------------------------------------------------- #


def test_the_compact_view_on_a_terminal_stops_at_the_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    """It ends by naming the fuller views, so the terminal is not flooded to show them."""

    monkeypatch.setattr(terminal_ui, "human_tty_stdout", lambda *_a, **_k: True)
    result = runner.invoke(app, ["profiles", "--format", "compact"])

    assert result.exit_code == 0, result.output
    assert "profiles --format table" in result.output
    assert "profiles --format detailed" in result.output


def test_the_table_view_on_a_terminal_does_not_stop_at_the_panel(monkeypatch: pytest.MonkeyPatch) -> None:
    """The counterpart: `--format table` was asked for the grid, and must produce it."""

    monkeypatch.setattr(terminal_ui, "human_tty_stdout", lambda *_a, **_k: True)
    result = runner.invoke(app, ["profiles", "--format", "table"])

    assert result.exit_code == 0, result.output
    assert "profiles --format table" not in result.output


def test_the_json_view_stays_machine_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A terminal must not change what a script receives."""

    monkeypatch.setattr(terminal_ui, "human_tty_stdout", lambda *_a, **_k: True)
    result = runner.invoke(app, ["profiles", "--format", "json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)


# --------------------------------------------------------------------------- #
# Failure shape
# --------------------------------------------------------------------------- #


def test_a_deliberate_exit_is_not_relabelled(monkeypatch: pytest.MonkeyPatch) -> None:
    def _exit(*_a: object, **_k: object) -> object:
        raise typer.Exit(code=4)

    monkeypatch.setattr(pr, "_iter_bundled_profiles", _exit)
    assert runner.invoke(app, ["profiles"]).exit_code == 4


def test_an_unexpected_failure_is_a_message_not_a_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> object:
        raise ZeroDivisionError("listing went sideways")

    monkeypatch.setattr(pr, "_iter_bundled_profiles", _boom)
    result = runner.invoke(app, ["profiles"])

    assert result.exit_code == 3
    assert "Traceback" not in result.output
