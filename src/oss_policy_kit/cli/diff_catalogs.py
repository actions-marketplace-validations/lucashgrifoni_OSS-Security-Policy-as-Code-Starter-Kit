"""``oss-policy-kit diff-catalogs`` subcommand (T1.4).

Shows the control + profile delta between two kit catalogs: a ``--from`` snapshot
(an older kit data directory or a bare ``catalog.yaml``) versus a ``--to`` snapshot
(defaults to the bundled catalog). Useful to understand what a kit upgrade changes
before adopting it — e.g. the new controls and the applicability default that came
with the v7.3.0 -> v8.0.0 bump.

Read-only and generated. The computation lives in
:mod:`oss_policy_kit.application.catalog_diff` (the single source of truth); this
module only parses flags and renders. It changes no ``evaluate`` verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from oss_policy_kit.application.catalog_diff import diff_catalogs, load_snapshot, render_human
from oss_policy_kit.application.loader import bundled_kit_root
from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_DISCOVER
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


def _run_diff_catalogs(from_path: Path, to_path: Path | None, output_format: str) -> None:
    fmt = output_format.lower().strip()
    if fmt not in {"human", "json"}:
        raise InvalidInputError("--format must be human or json.")
    old = load_snapshot(from_path, label=str(from_path))
    if to_path is not None:
        new = load_snapshot(to_path, label=str(to_path))
    else:
        new = load_snapshot(bundled_kit_root(), label="bundled")
    diff = diff_catalogs(old, new)
    if fmt == "json":
        write_stdout_text(json.dumps(diff.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        write_stdout_text(render_human(diff))


@app.command("diff-catalogs", rich_help_panel=CMD_PANEL_DISCOVER)
def diff_catalogs_cmd(
    from_path: Path = typer.Option(
        ...,
        "--from",
        help="Older kit data dir (or a catalog.yaml file) to diff FROM.",
    ),
    to_path: Path | None = typer.Option(
        None,
        "--to",
        help="Newer kit data dir (or catalog.yaml) to diff TO. Default: the bundled catalog.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help="Output format: human (default) or json.",
    ),
) -> None:
    """Show the control + profile delta between two kit catalogs.

    Compares a ``--from`` snapshot against a ``--to`` snapshot (default: the bundled
    catalog) and reports the added / removed / changed controls (title, category,
    automation, lifecycle, assurance, weight) plus added / removed profiles and
    per-profile control membership changes. Each snapshot is a kit data directory
    (with ``controls/catalog.yaml`` and ``profiles/``) or a bare ``catalog.yaml``
    for a controls-only diff. Read-only and advisory; changes no ``evaluate`` verdict.

    Exit codes: 0 success (informational); 2 usage error; 3 unexpected internal error.
    """

    try:
        _run_diff_catalogs(from_path, to_path, output_format)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message, no traceback leak
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
