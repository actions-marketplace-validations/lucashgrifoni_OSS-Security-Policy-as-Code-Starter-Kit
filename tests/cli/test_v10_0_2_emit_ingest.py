"""v10.0.2 regressions for the emit-insights / ingest-insights / ingest-scorecard group.

Two confirmed defects found by the extreme end-user raio-x:

- #20 (MED, non-determinism): ``emit-insights`` derived ``header.last-updated`` /
  ``header.last-reviewed`` from ``datetime.now(UTC)`` (via ``_now_iso8601_z``),
  ignoring ``SOURCE_DATE_EPOCH``. Two runs — and any reproducible build — produced
  a non-identical ``security-insights.yml``. Fixed by routing the clock through the
  SDE-honouring ``oss_policy_kit.domain.models.utc_now``.

- ``--target`` relative-path leak (M-002): all three commands did
  ``target_path = target.resolve()`` and then echoed the RESOLVED absolute path in
  the "is not a directory" error, leaking the auditor's cwd / home directory /
  OS username. Fixed by echoing the user-supplied ``--target`` string verbatim.

Both are driven through the real CLI app (Typer ``CliRunner``) so the fixes are
exercised end-to-end, mirroring the v10.0.1 ``correlate-findings`` M-002 test.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from oss_policy_kit.cli.emit_insights import _build_insights_document
from oss_policy_kit.cli.main import app

runner = CliRunner()

# 1781524800 == 2026-06-15T12:00:00Z (the epoch the suite conftest pins).
_PINNED_EPOCH = "1781524800"
_PINNED_Z = "2026-06-15T12:00:00Z"


# --------------------------------------------------------------------------- #
# #20  emit-insights determinism under SOURCE_DATE_EPOCH
# --------------------------------------------------------------------------- #


def test_build_document_timestamps_honour_sde(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``_build_insights_document`` pins its header timestamps to SOURCE_DATE_EPOCH.

    Before the fix ``_now_iso8601_z`` read ``datetime.now(UTC)`` and returned the real
    wall-clock date regardless of the pinned epoch.
    """
    monkeypatch.setenv("SOURCE_DATE_EPOCH", _PINNED_EPOCH)
    doc = _build_insights_document(tmp_path)
    assert doc["header"]["last-updated"] == _PINNED_Z
    assert doc["header"]["last-reviewed"] == _PINNED_Z


def test_emit_insights_byte_identical_under_pinned_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The determinism fence: two emit-insights runs under a pinned epoch are byte-identical,
    and the pinned timestamp (not today's wall clock) is what lands in the YAML."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", _PINNED_EPOCH)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").write_text("# Security\nReport to security@example.com\n", encoding="utf-8")

    out_a = tmp_path / "a.yml"
    out_b = tmp_path / "b.yml"
    r1 = runner.invoke(app, ["emit-insights", "--target", str(repo), "--output", str(out_a)])
    r2 = runner.invoke(app, ["emit-insights", "--target", str(repo), "--output", str(out_b)])
    assert r1.exit_code == 0, r1.output
    assert r2.exit_code == 0, r2.output

    doc = yaml.safe_load(out_a.read_text(encoding="utf-8"))
    assert doc["header"]["last-updated"] == _PINNED_Z
    assert doc["header"]["last-reviewed"] == _PINNED_Z
    # Reproducible-builds guarantee: same input + same pinned epoch => identical bytes.
    assert out_a.read_bytes() == out_b.read_bytes()


# --------------------------------------------------------------------------- #
# --target relative-path leak (M-002) across all three commands
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cmd", ["emit-insights", "ingest-insights", "ingest-scorecard"])
def test_bad_target_echoes_user_string_not_resolved_path(
    cmd: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative --target is echoed verbatim, never as its resolved absolute path (M-002).

    Echoing back the string the user typed is not a leak; resolving it is, because the
    resolved form exposes the cwd / home directory (and the OS username with it). The
    target must therefore be RELATIVE here: given an absolute --target the user's own
    string already is the absolute path, so there is nothing the error could withhold.
    """
    (tmp_path / "SECRET-HOME").mkdir()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, [cmd, "--target", "SECRET-HOME/nope"])
    assert result.exit_code == 2, result.output
    assert "is not a directory" in result.output
    # Robust discriminator (dodges the Windows 8.3 short-path trap): the echoed value must
    # sit DIRECTLY after ``--target `` with no absolute prefix. A resolved leak would prepend
    # the absolute home/cwd prefix before ``SECRET-HOME``, so ``--target SECRET-HOME`` would
    # NOT be a substring; the verbatim echo (relative, no prefix) is.
    typed_value = str(Path("SECRET-HOME/nope"))  # OS-native separator, still relative
    assert f"--target {typed_value}" in result.output
    assert "--target SECRET-HOME" in result.output
    # Secondary guard: the resolved absolute form must be absent (unreliable on Windows
    # for a non-existent tail, but a valid extra check on POSIX / existing paths).
    assert str(tmp_path.resolve()) not in result.output
    assert "Traceback" not in result.output
