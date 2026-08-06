"""`evaluate-many` subcommand for monorepo / multi-app roots."""

from __future__ import annotations

from pathlib import Path

import typer

from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.cli.common import (
    app,
    markup_safe,
    stderr_console,
    warn_if_batch_skipped_directories,
)
from oss_policy_kit.cli.help_text import CMD_PANEL_EVALUATE, EVALUATE_MANY_EPILOG
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError


@app.command("evaluate-many", epilog=EVALUATE_MANY_EPILOG, rich_help_panel=CMD_PANEL_EVALUATE)
def evaluate_many_cmd(
    target_root: Path = typer.Option(
        ...,
        "--target-root",
        help="Directory whose immediate child folders are evaluated as separate repositories.",
    ),
    profiles: str = typer.Option(
        ...,
        "--profiles",
        "-p",
        help="Comma-separated profile ids (for example: github-level-1,azure-level-1).",
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        help="Directory for consolidated batch reports and per-target subfolders.",
    ),
    kit_root: Path | None = typer.Option(None, "--kit-root", "-k", help="Override bundled controls/ and profiles/."),
    include: str | None = typer.Option(
        None,
        "--include",
        help="Optional fnmatch pattern applied to child directory names (for example: lab-*).",
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help="Optional fnmatch pattern applied to child directory names to skip.",
    ),
    fail_on: str = typer.Option(
        "none",
        "--fail-on",
        "-fo",
        help=(
            "CI gate mode: none, fail, or degraded. "
            "none=never fail from result statuses; fail=exit 1 on any fail; "
            "degraded=exit 1 on fail or manual-review-required. "
            "Operational warnings alone do not trigger this gate."
        ),
    ),
    skip_non_repos: bool = typer.Option(
        False,
        "--skip-non-repos",
        help=(
            "Skip child directories that don't look like a repository root. "
            "Detection requires at least one primary signal: .git, a build "
            "manifest (package.json, pyproject.toml, requirements.txt, go.mod, "
            "Cargo.toml, pom.xml, etc.), a CI file (.github/workflows/, "
            "azure-pipelines.yml, pipelines/azure/*.yml, buildspec.yml), or a Dockerfile. "
            "README.md alone is NOT sufficient. Output / build / cache directories "
            "(out, dist, build, _output, .tmp, node_modules, venv, .venv, target, site, "
            "coverage, htmlcov, plus out-* / build-* / dist-* / output-* prefixes) "
            "are also skipped even when they happen to contain a manifest."
        ),
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress incremental stderr progress lines; keep final batch summary writes.",
    ),
    include_absolute_path: bool = typer.Option(
        False,
        "--include-absolute-path",
        help=(
            "Keep full absolute paths in the batch reports (target_root, per-run target_path, "
            "report artifact paths, skipped-directory paths). Default is privacy-by-default: "
            "every path is sanitized to a basename so shared batch artifacts do not leak the "
            "auditor's home directory or username. Use only when downstream tooling expects "
            "absolute paths."
        ),
    ),
) -> None:
    """Evaluate many repository clones under one parent directory (monorepo / multi-app root)."""

    try:
        root = resolve_existing_dir(str(target_root))
        profile_ids = [p.strip() for p in profiles.split(",") if p.strip()]
        if not profile_ids:
            raise InvalidInputError("Provide at least one profile in --profiles.")
        policy = fail_on.lower()
        if policy not in {"none", "fail", "degraded"}:
            raise InvalidInputError("--fail-on must be one of: none, fail, degraded.")

        progress_cb = None
        if not quiet:
            cons = stderr_console()

            def progress_cb(repo_name: str, current: int, total: int) -> None:
                cons.print(f"[dim]  [{current}/{total}][/dim] {repo_name}")

        batch = run_batch_evaluation(
            target_root=root,
            profile_ids=profile_ids,
            output_dir=output_dir.resolve(),
            kit_root=kit_root,
            include=include,
            exclude=exclude,
            fail_on=policy,
            skip_non_repos=skip_non_repos,
            progress_callback=progress_cb,
            include_absolute_path=include_absolute_path,
        )
        stderr_console().print(f"[green]Wrote[/green] {markup_safe(batch.batch_json.resolve())}")
        stderr_console().print(f"[green]Wrote[/green] {markup_safe(batch.batch_md.resolve())}")
        if not quiet:
            warn_if_batch_skipped_directories(batch.batch_json)
        if batch.gate_violated:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        stderr_console().print(f"[red]Unexpected error:[/red] {markup_safe(exc)}")
        raise typer.Exit(code=3) from exc
