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
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_DISCOVER
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


def _reject_unusable_snapshot(path: Path, flag: str) -> None:
    """Refuse a missing / catalog-less snapshot while citing only what the user typed.

    ``load_snapshot`` reports the *resolved* path, which turns a relative ``--from zzz``
    into an absolute one carrying the auditor's home directory and OS username (M-002).
    Checking here lets the message echo the flag value verbatim; everything the snapshot
    loader still raises (a malformed catalog, an unreadable profile) is about file
    content, not about where the file lives.
    """

    try:
        resolved = path.expanduser().resolve()
        exists = resolved.exists()
    except OSError:  # pragma: no cover - resolve rarely raises here
        resolved, exists = path, False
    if not exists:
        raise InvalidInputError(
            f"{flag} {path} does not exist. Point {flag} at a kit data directory "
            "(containing controls/catalog.yaml) or directly at a catalog.yaml file."
        )
    if resolved.is_dir() and not (resolved / "controls" / "catalog.yaml").is_file():
        raise InvalidInputError(
            f"No control catalog found for {flag} {path} (expected controls/catalog.yaml "
            "under it). Point it at a kit data directory or directly at a catalog.yaml file."
        )


def _run_diff_catalogs(from_path: Path, to_path: Path | None, output_format: str) -> None:
    fmt = output_format.lower().strip()
    if fmt not in {"human", "json"}:
        raise InvalidInputError("--format must be human or json.")
    # Both flags are checked before either snapshot is loaded, so a usage error on one
    # side is not masked by a content error on the other.
    _reject_unusable_snapshot(from_path, "--from")
    if to_path is not None:
        _reject_unusable_snapshot(to_path, "--to")
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
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message, no traceback leak
        exit_for_unexpected(exc)
