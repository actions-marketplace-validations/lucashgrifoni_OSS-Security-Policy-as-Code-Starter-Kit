"""Integration tests: profile table rendering respects patched terminal width via ``terminal_ui``.

``main`` resolves layout through ``terminal_ui.terminal_width``, so patching
``oss_policy_kit.cli.terminal_ui.terminal_width`` affects the Rich table without stale imports.
"""

from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from oss_policy_kit.cli import main as cli_main
from oss_policy_kit.cli import terminal_ui

# Bundled github-level-1 audience (full YAML text); compact ``profiles`` maps this to an executive summary.
_FULL_GITHUB_L1_AUDIENCE_SNIPPET = "adopting a minimal, honest"
# Distinctive tokens that appear together only in the full YAML audience for ``github-level-1`` (detailed table).
_GITHUB_L1_AUDIENCE_MARKERS = ("Maintainers", "adopting", "minimal", "honest")


def _squash_ws(text: str) -> str:
    """Collapse whitespace so wrapped Rich cells still match full phrases."""

    return re.sub(r"\s+", " ", text).strip()


def _strip_box_drawing(text: str) -> str:
    """Remove Rich table borders/separators so audience/description phrases stay readable."""

    no_lines = re.sub(r"[\u2500-\u257f]+", " ", text)
    return _squash_ws(no_lines)


def _invoke_with_stdout_width(runner: CliRunner, monkeypatch: pytest.MonkeyPatch, width: int, args: list[str]) -> str:
    monkeypatch.setattr(
        terminal_ui,
        "terminal_width",
        lambda _stream, fallback=120: width,
    )
    result = runner.invoke(cli_main.app, args)
    assert result.exit_code == 0, result.output
    return result.stdout or ""


def test_profiles_compact_narrow_vs_wide_outputs_differ_and_narrow_wraps_more(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Smaller terminal columns fold Rich cells onto more lines than a very wide terminal."""

    runner = CliRunner()
    # Wide enough to avoid ellipsis truncation on profile ids, narrow enough to wrap more than a very wide console.
    narrow = _invoke_with_stdout_width(runner, monkeypatch, 88, ["profiles"])
    wide = _invoke_with_stdout_width(runner, monkeypatch, 280, ["profiles"])

    assert narrow != wide
    assert narrow.count("\n") > wide.count("\n") + 25
    assert "Bundled profiles" in narrow and "Bundled profiles" in wide
    assert "github-level-1" in narrow and "github-level-1" in wide
    # Compact table should keep audience/description short (no full YAML audience phrase).
    assert _FULL_GITHUB_L1_AUDIENCE_SNIPPET not in _strip_box_drawing(narrow)
    assert _FULL_GITHUB_L1_AUDIENCE_SNIPPET not in _strip_box_drawing(wide)


def test_show_profiles_detailed_narrow_vs_wide_outputs_differ_and_narrow_wraps_more(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detailed audience/description columns wrap more aggressively when the terminal is narrow."""

    runner = CliRunner()
    narrow = _invoke_with_stdout_width(runner, monkeypatch, 88, ["--show-profiles"])
    wide = _invoke_with_stdout_width(runner, monkeypatch, 280, ["--show-profiles"])

    assert narrow != wide
    assert narrow.count("\n") > wide.count("\n") + 25
    squished_wide = _strip_box_drawing(wide)
    for marker in _GITHUB_L1_AUDIENCE_MARKERS:
        assert marker in squished_wide

    letter_run = "".join(re.findall(r"[A-Za-z]+", narrow))
    # Narrow tables wrap aggressively; bundled YAML tokens may not stay contiguous once borders are stripped.
    assert "minimal" in letter_run and "adopting" in letter_run and "honest" in letter_run
    # github-level-1 row: long audience text fits on fewer physical lines when the table is wide.
    narrow_l1 = [ln for ln in narrow.splitlines() if "github-level-1" in ln]
    wide_l1 = [ln for ln in wide.splitlines() if "github-level-1" in ln]
    assert narrow_l1 and wide_l1
    assert max(len(ln) for ln in wide_l1) > max(len(ln) for ln in narrow_l1)


def test_compact_profiles_differs_from_show_profiles_detailed_at_same_width(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compact vs detailed uses different cell text; full YAML audience appears only in ``--show-profiles``."""

    runner = CliRunner()
    width = 200
    compact = _invoke_with_stdout_width(runner, monkeypatch, width, ["profiles"])
    detailed = _invoke_with_stdout_width(runner, monkeypatch, width, ["--show-profiles"])

    compact_clean = _strip_box_drawing(compact)
    detailed_clean = _strip_box_drawing(detailed)
    assert _FULL_GITHUB_L1_AUDIENCE_SNIPPET not in compact_clean
    for marker in _GITHUB_L1_AUDIENCE_MARKERS:
        assert marker in detailed_clean
    assert detailed.count("\n") > compact.count("\n")


def test_patching_terminal_ui_terminal_width_is_the_hook_used_by_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanity check: layout responds to ``terminal_ui.terminal_width`` (module path used by ``main``)."""

    recorded: list[int] = []

    def _capture_width(stream: object, fallback: int = 120) -> int:
        recorded.append(72)
        return 72

    monkeypatch.setattr(terminal_ui, "terminal_width", _capture_width)
    runner = CliRunner()
    result = runner.invoke(cli_main.app, ["profiles"])
    assert result.exit_code == 0
    assert recorded == [72]
