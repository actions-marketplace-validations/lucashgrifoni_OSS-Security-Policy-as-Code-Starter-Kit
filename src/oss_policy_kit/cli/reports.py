"""`diff-reports` subcommand: drift between two evaluation reports."""

from __future__ import annotations

from pathlib import Path

import typer

from oss_policy_kit.application.drift import compute_drift, load_report_json
from oss_policy_kit.application.reporting import render_drift_report
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EVALUATE, DIFF_REPORTS_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError

# Formats accepted by render_drift_report. Validated here (consistent with the other
# subcommands) so a typo like ``--format markdwn`` fails loudly with exit 2 instead of
# silently falling back to the Rich table and corrupting a CI artifact.
_DIFF_FORMATS: tuple[str, ...] = ("table", "json", "markdown", "md")


@app.command("diff-reports", epilog=DIFF_REPORTS_EPILOG, rich_help_panel=CMD_PANEL_EVALUATE)
def diff_reports_cmd(
    before: Path = typer.Option(..., "--before", help="Path to the earlier evaluation-report.json."),
    after: Path = typer.Option(..., "--after", help="Path to the more recent evaluation-report.json."),
    fmt: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, markdown.",
        case_sensitive=False,
    ),
    fail_on_regression: bool = typer.Option(
        True,
        "--fail-on-regression/--no-fail-on-regression",
        help="Exit with code 1 when regressions are present (default: enabled).",
    ),
    include_absolute_path: bool = typer.Option(
        False,
        "--include-absolute-path",
        help=(
            "Keep the full absolute input paths in the rendered drift report. Default is "
            "privacy-by-default: the Before/After paths are sanitized to the report file's "
            "basename. Use this flag only when downstream tooling specifically expects an "
            "absolute path; the markdown output is meant to be pasted into a PR comment, "
            "and absolute paths there leak the auditor's home directory or username."
        ),
    ),
) -> None:
    """Compare two evaluation reports and show posture drift."""

    try:
        if fmt.strip().lower() not in _DIFF_FORMATS:
            raise InvalidInputError(f"--format must be one of: {', '.join(_DIFF_FORMATS)} (got {fmt!r}).")
        if not before.is_file():
            raise InvalidInputError(f"--before not found: {before}")
        if not after.is_file():
            raise InvalidInputError(f"--after not found: {after}")
        # The label names the side, so a malformed --before and a malformed --after can no
        # longer produce byte-identical rejections ("Expecting value: line 1 column 1").
        b = load_report_json(before, label="--before report")
        a = load_report_json(after, label="--after report")
        drift = compute_drift(b, a, include_absolute_path=include_absolute_path)
        if drift.profile_mismatch:
            stderr_console().print(
                "[yellow]Warning:[/yellow] profiles differ "
                f"([cyan]{drift.before_profile_id}[/cyan] → [cyan]{drift.after_profile_id}[/cyan]). "
                "Controls listed under 'New in after' or 'Removed from after' may reflect "
                "a profile scope change rather than a posture change."
            )
        text = render_drift_report(drift, fmt, color=terminal_ui.human_tty_stdout())
        write_stdout_text(text)
        if drift.has_regressions and fail_on_regression:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except ValueError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc)}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)
