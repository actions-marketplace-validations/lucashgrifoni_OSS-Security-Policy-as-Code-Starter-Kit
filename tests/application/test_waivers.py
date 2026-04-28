"""Waiver parsing and expiry."""

from pathlib import Path

from tests.conftest import ROOT

from oss_policy_kit.application.waivers import parse_waivers_file


def test_expired_waiver_ignored(tmp_path: Path) -> None:
    p = tmp_path / "w.yaml"
    p.write_text(
        """
version: 1
waivers:
  - control_id: CI-DANGER-007
    justification: "legacy"
    owner: "a@b.com"
    status: approved
    expires_at: "2000-01-01"
""",
        encoding="utf-8",
    )
    out = parse_waivers_file(p)
    assert "CI-DANGER-007" not in out.by_control
    assert any("expired" in w.lower() for w in out.warnings)


def test_invalid_justification_skipped(tmp_path: Path) -> None:
    p = tmp_path / "w.yaml"
    p.write_text(
        """
version: 1
waivers:
  - control_id: X
    justification: ""
    owner: "a@b.com"
""",
        encoding="utf-8",
    )
    out = parse_waivers_file(p)
    assert "X" not in out.by_control


def test_example_waiver_file_loads() -> None:
    path = ROOT / "waivers" / "waivers.example.yaml"
    out = parse_waivers_file(path)
    assert "CI-DANGER-007" in out.by_control
