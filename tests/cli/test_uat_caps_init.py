"""UAT bucket ``caps-init``: input-size caps on the findings surface + a reproducible ``init``.

Two independent user-visible defects:

- ``correlate-findings --waivers`` had no size cap, so the same waivers file that
  ``evaluate --waivers`` refuses at 5 MiB was instead read in full and then dropped.
- ``init`` read the wall clock directly, so ``oss-policy-kit.yaml`` differed between
  two runs of a reproducible build.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import Result
from typer.testing import CliRunner

from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES
from oss_policy_kit.cli.main import app, prepare_cli_args

runner = CliRunner()

_PINNED_EPOCH = "1700000000"
_PINNED_STAMP = "2023-11-14T22:13:20Z"
_OTHER_EPOCH = "1600000000"
_OTHER_STAMP = "2020-09-13T12:26:40Z"


def _invoke(args: list[str]) -> Result:
    return runner.invoke(app, prepare_cli_args(args))


def _write_oversized_waivers(path: Path) -> None:
    """Write a syntactically valid waivers file just past ``MAX_EVIDENCE_BYTES``."""

    body = (
        "waivers:\n"
        "  - control_id: GH-PIN-007\n"
        "    owner: appsec-team\n"
        "    justification: accepted for the pilot repository\n"
        "    vulnerability_ids:\n"
        "      - CVE-2024-0001\n"
    )
    padding = "# padding to exceed the evidence size cap\n" * ((MAX_EVIDENCE_BYTES // 42) + 1)
    path.write_text(body + padding, encoding="utf-8")
    assert path.stat().st_size > MAX_EVIDENCE_BYTES


# --------------------------------------------------------------------------- #
# size-cap-waivers
# --------------------------------------------------------------------------- #


def test_correlate_findings_refuses_oversized_waivers(tmp_path: Path) -> None:
    """An oversized waivers file must be refused, not read for seconds and then ignored.

    Silently proceeding with zero waivers makes a suppressed finding reappear as a
    gate failure with no explanation of why the operator's waivers did not apply.
    """

    waivers = tmp_path / "waivers.yaml"
    _write_oversized_waivers(waivers)

    result = _invoke(
        [
            "correlate-findings",
            "--target",
            str(tmp_path),
            "--output",
            str(tmp_path / "findings.json"),
            "--waivers",
            str(waivers),
        ]
    )

    assert result.exit_code == 2, result.output
    combined = result.output
    assert "waivers.yaml" in combined.lower()
    assert "exceeding" in combined
    # The refusal must not become a new path-leak surface (M-002).
    assert str(tmp_path) not in combined


def test_correlate_findings_accepts_waivers_under_the_cap(tmp_path: Path) -> None:
    """The cap must only reject oversized input: a normal waivers file still applies."""

    waivers = tmp_path / "waivers.yaml"
    waivers.write_text(
        "waivers:\n"
        "  - control_id: GH-PIN-007\n"
        "    owner: appsec-team\n"
        "    justification: accepted for the pilot repository\n"
        "    vulnerability_ids:\n"
        "      - CVE-2024-0001\n",
        encoding="utf-8",
    )

    result = _invoke(
        [
            "correlate-findings",
            "--target",
            str(tmp_path),
            "--output",
            str(tmp_path / "findings.json"),
            "--waivers",
            str(waivers),
        ]
    )

    assert result.exit_code == 0, result.output


# --------------------------------------------------------------------------- #
# init-epoch
# --------------------------------------------------------------------------- #


def test_init_config_honours_source_date_epoch(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """``oss-policy-kit.yaml`` must carry the pinned epoch, not the builder's wall clock.

    A reproducible build that pins ``SOURCE_DATE_EPOCH`` otherwise gets a config file
    whose checksum changes on every run, breaking artifact comparison.
    """

    monkeypatch.setenv("SOURCE_DATE_EPOCH", _PINNED_EPOCH)

    result = _invoke(["init", "--target", str(tmp_path), "--yes"])

    assert result.exit_code == 0, result.output
    config = (tmp_path / "oss-policy-kit.yaml").read_text(encoding="utf-8")
    assert f"generated_at: {_PINNED_STAMP}" in config
    assert f"on {_PINNED_STAMP}." in config


def test_init_config_tracks_the_epoch_and_nothing_else(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Changing the epoch must be the *only* thing that changes the generated config.

    Proves both directions: the wall clock never leaks in, and the timestamps are the
    sole run-to-run variance — so a rebuild can be byte-compared against the original.
    """

    config = tmp_path / "oss-policy-kit.yaml"

    monkeypatch.setenv("SOURCE_DATE_EPOCH", _PINNED_EPOCH)
    assert _invoke(["init", "--target", str(tmp_path), "--yes"]).exit_code == 0
    first = config.read_text(encoding="utf-8")

    monkeypatch.setenv("SOURCE_DATE_EPOCH", _OTHER_EPOCH)
    assert _invoke(["init", "--target", str(tmp_path), "--yes", "--force"]).exit_code == 0
    second = config.read_text(encoding="utf-8")

    assert _PINNED_STAMP in first
    assert _OTHER_STAMP not in first
    assert _OTHER_STAMP in second
    assert _PINNED_STAMP not in second
    assert first.replace(_PINNED_STAMP, _OTHER_STAMP) == second
