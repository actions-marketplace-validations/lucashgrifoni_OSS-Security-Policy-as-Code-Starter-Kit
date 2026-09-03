"""CLI tests for the ``diff-catalogs`` subcommand (T1.4).

Subprocess runs use a deterministic terminal (mirrors test_osps_coverage); in-process
CliRunner runs drive the render branches and assert exit codes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml
from typer.testing import CliRunner

from oss_policy_kit.cli.main import app

ROOT = Path(__file__).parents[2]
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_runner = CliRunner()


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT)])
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    env["COLUMNS"] = "200"
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "oss_policy_kit", *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )


def _write_kit(root: Path, controls: list[dict[str, object]], profiles: dict[str, list[str]]) -> Path:
    (root / "controls").mkdir(parents=True, exist_ok=True)
    (root / "controls" / "catalog.yaml").write_text(yaml.safe_dump({"controls": controls}), encoding="utf-8")
    profiles_dir = root / "profiles"
    profiles_dir.mkdir(exist_ok=True)
    for pid, control_ids in profiles.items():
        pdir = profiles_dir / pid
        pdir.mkdir(exist_ok=True)
        (pdir / "profile.yaml").write_text(
            yaml.safe_dump({"id": pid, "title": pid, "controls": control_ids}), encoding="utf-8"
        )
    return root


def _two_kits(tmp_path: Path) -> tuple[Path, Path]:
    old = _write_kit(
        tmp_path / "old",
        controls=[
            {"id": "A", "title": "Control A", "category": "governance", "automation": "automated"},
            {"id": "B", "title": "Control B", "category": "ci", "automation": "automated"},
        ],
        profiles={"p1": ["A", "B"]},
    )
    new = _write_kit(
        tmp_path / "new",
        controls=[
            {"id": "A", "title": "Control A", "category": "governance", "automation": "automated"},
            {"id": "C", "title": "Control C", "category": "release", "automation": "manual"},
        ],
        profiles={"p1": ["A", "C"]},
    )
    return old, new


def test_cli_help_lists_diff_catalogs() -> None:
    proc = _run(["--help"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "diff-catalogs" in "".join(_ANSI_RE.sub("", proc.stdout + proc.stderr).split())


def test_cli_human_output(tmp_path: Path) -> None:
    old, new = _two_kits(tmp_path)
    proc = _run(["diff-catalogs", "--from", str(old), "--to", str(new)])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    out = proc.stdout
    assert "+ C  Control C" in out  # added control
    assert "- B  Control B" in out  # removed control
    assert "~ p1" in out  # profile membership changed
    assert "changes no evaluate verdict" in out


def test_cli_json_output_shape(tmp_path: Path) -> None:
    old, new = _two_kits(tmp_path)
    proc = _run(["diff-catalogs", "--from", str(old), "--to", str(new), "--format", "json"])
    assert proc.returncode == 0, proc.stderr + proc.stdout
    payload = json.loads(proc.stdout)
    assert payload["controls"]["added"] == [{"id": "C", "title": "Control C"}]
    assert payload["controls"]["removed"] == [{"id": "B", "title": "Control B"}]
    assert payload["profiles_compared"] is True
    assert payload["profiles"]["changed"][0]["id"] == "p1"


def test_cli_default_to_is_bundled(tmp_path: Path) -> None:
    # With no --to, the new side is the bundled catalog (221 controls), so a tiny
    # --from yields many "added" controls. Just assert it runs and parses.
    old, _ = _two_kits(tmp_path)
    res = _runner.invoke(app, ["diff-catalogs", "--from", str(old), "--format", "json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["to"] == "bundled"
    assert len(payload["controls"]["added"]) > 50  # bundled has far more controls


def test_cli_bad_format_exits_2(tmp_path: Path) -> None:
    old, new = _two_kits(tmp_path)
    res = _runner.invoke(app, ["diff-catalogs", "--from", str(old), "--to", str(new), "--format", "xml"])
    assert res.exit_code == 2, res.output


def test_cli_missing_from_exits_2(tmp_path: Path) -> None:
    res = _runner.invoke(app, ["diff-catalogs", "--from", str(tmp_path / "nope")])
    assert res.exit_code == 2, res.output
