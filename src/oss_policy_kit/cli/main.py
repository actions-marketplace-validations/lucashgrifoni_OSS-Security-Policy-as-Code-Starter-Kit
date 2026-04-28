"""Typer entrypoint for oss-policy-kit."""

from __future__ import annotations

import json
import os
import sys
import textwrap
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import click
import typer
from rich.console import Console
from rich.table import Table
from typer import Context
from typer.core import HAS_RICH, TyperGroup

from oss_policy_kit import __version__ as kit_version
from oss_policy_kit.adapters.local_paths import resolve_existing_dir
from oss_policy_kit.adapters.scorecard_json import load_scorecard_auto
from oss_policy_kit.application.batch_evaluate import run_batch_evaluation
from oss_policy_kit.application.cli_output import FailOnPolicy, fail_on_violated, print_stdout_summary
from oss_policy_kit.application.drift import compute_drift, load_report_json
from oss_policy_kit.application.engine import evaluate_repository
from oss_policy_kit.application.evidence_scaffold import scaffold_evidence_files
from oss_policy_kit.application.loader import (
    BUNDLED_PROFILE_LEGACY_IDS,
    PROFILE_DIRECTORY_ALIASES,
    ControlSpec,
    load_catalog,
    load_profile_by_id,
    merge_kit_root,
)
from oss_policy_kit.application.profile_hints import build_profile_recommendation
from oss_policy_kit.application.reporting import render_drift_report, write_reports
from oss_policy_kit.application.waivers import parse_waivers_file
from oss_policy_kit.cli import terminal_ui
from oss_policy_kit.domain.errors import InvalidInputError, LoadError, OssPolicyKitError
from oss_policy_kit.infrastructure.collectors.aws_collector import AWSEvidenceCollector
from oss_policy_kit.infrastructure.collectors.azure_collector import AzureDevOpsEvidenceCollector
from oss_policy_kit.infrastructure.collectors.github_collector import GitHubEvidenceCollector
from oss_policy_kit.infrastructure.git_remote import read_github_repo_slug_from_git_config

# Typer/Rich collapses single newlines inside each epilog paragraph; use "\n\n" between
# every logical line so `typer.rich_utils.rich_format_help` preserves row breaks.
_ROOT_CLI_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Baseline evaluation (writes reports under ./out):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1",
        "Compatibility (root flags, no subcommand):",
        "  python -m oss_policy_kit --target . --profile github-level-1",
        "CI gate (exit 1 when any control is fail):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail",
        "JSON summary on stdout:",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --format json --summary-only",
        "List bundled profiles (compact table on stdout):",
        "  python -m oss_policy_kit profiles",
        "Show bundled profiles with full audience/description via root flag:",
        "  python -m oss_policy_kit --show-profiles",
        "Profiles as JSON:",
        "  python -m oss_policy_kit profiles --format json",
        "Many repos under one parent folder:",
        "  python -m oss_policy_kit evaluate-many --target-root ./repos --profiles github-level-1,azure-level-1",
        "Evidence JSON templates (release-hardening):",
        "  python -m oss_policy_kit scaffold-evidence --target . --platform github",
        "Heuristic profile suggestions:",
        "  python -m oss_policy_kit recommend-profile --target .",
        "",
        "----------------------------------------------------------------------",
        "EXIT CODES",
        "----------------------------------------------------------------------",
        "  0  Success; fail-on threshold not violated (when --fail-on applies).",
        "  1  Evaluation finished; fail-on threshold violated.",
        "  2  Invalid usage, missing input, or validation/load error.",
        "  3  Unexpected internal error.",
        "",
        "----------------------------------------------------------------------",
        "WINDOWS",
        "----------------------------------------------------------------------",
        "Prefer python -m oss_policy_kit if the oss-policy-kit script is not on PATH.",
    ]
)

_EVALUATE_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Baseline (reports under ./out):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1",
        "Positional target (when the path has no spaces):",
        "  python -m oss_policy_kit evaluate . --profile github-level-1",
        "JSON summary on stdout:",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --summary-only --format json",
        "CI gate (fail severity):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail",
        "CI gate (fail or manual-review-required):",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on degraded",
        "Custom output dir and waivers file:",
        (
            "  python -m oss_policy_kit evaluate -t . --profile github-release-hardening-1 "
            "-o ./reports --waivers ./waivers/waivers.example.yaml"
        ),
        "Optional OpenSSF Scorecard JSON:",
        "  python -m oss_policy_kit evaluate --target . --profile github-level-1 --scorecard-json ./scorecard.json",
        "",
        "----------------------------------------------------------------------",
        "FAIL-ON MODES",
        "----------------------------------------------------------------------",
        "  none       Never fail (exit 0 unless internal error).",
        "  fail       Exit 1 if any control has status 'fail'.",
        "  degraded   Exit 1 if any control has 'fail' OR 'manual-review-required'.",
        "             Operational warnings alone do NOT trigger this gate.",
        "",
        "----------------------------------------------------------------------",
        "EXIT CODES",
        "----------------------------------------------------------------------",
        "  0  Evaluation completed; fail-on threshold not violated.",
        "  1  Evaluation completed; fail-on threshold violated.",
        "  2  Invalid usage, missing input, or validation/load error.",
        "  3  Unexpected internal error.",
    ]
)


class OssPolicyKitTyperGroup(TyperGroup):
    """Root Click group: prepend the ASCII banner before Typer plain or Rich help."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        use_rich = bool(HAS_RICH and self.rich_markup_mode is not None)
        if not use_rich:
            terminal_ui.write_cli_banner_to_formatter(formatter)
            return super().format_help(ctx, formatter)

        terminal_ui.print_cli_banner_before_typer_rich_help()
        from typer import rich_utils as typer_rich_utils

        rich_mode = self.rich_markup_mode
        if rich_mode is None:
            return super().format_help(ctx, formatter)
        return typer_rich_utils.rich_format_help(
            obj=self,
            ctx=ctx,
            markup_mode=rich_mode,
        )


app = typer.Typer(
    name="oss-policy-kit",
    cls=OssPolicyKitTyperGroup,
    no_args_is_help=True,
    add_completion=False,
    context_settings={"help_option_names": ["--help", "-h"]},
    help=(
        "Evaluate a local repository clone against bundled OSS security profiles.\n\n"
        "Preferred usage:\n"
        "  python -m oss_policy_kit evaluate --target <repo> --profile <profile>\n\n"
        "Compatibility usage:\n"
        "  python -m oss_policy_kit --target <repo> --profile <profile>"
    ),
    epilog=_ROOT_CLI_EPILOG,
)


def _stderr_console() -> Console:
    """Rich console for stderr human messages (rebuilt so width tracks current ``sys.stderr``)."""

    return terminal_ui.build_stderr_console()


def _warn_if_batch_skipped_directories(batch_json_path: Path) -> None:
    """Print a short stderr summary when the consolidated batch skipped one or more directories.

    Reads the batch JSON that `evaluate-many` just wrote and, if `skipped_directories` is non-empty,
    emits a single yellow line pointing operators at `evaluation-batch.json.skipped_directories`.
    Does not alter the batch JSON, the exit code, or the batch contract; fails silently if the file
    cannot be read for any reason (the main flow is the source of truth).
    """

    try:
        with batch_json_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return
    skipped = payload.get("skipped_directories")
    if not isinstance(skipped, list) or not skipped:
        return
    count = len(skipped)
    suffix = "y" if count == 1 else "ies"
    _stderr_console().print(
        f"[yellow]Skipped {count} director{suffix}[/yellow] under --skip-non-repos "
        f"(see {batch_json_path.name}.skipped_directories for details)."
    )


def _write_stdout_text(text: str) -> None:
    """Write *text* to stdout; fall back to UTF-8 bytes when the console codepage cannot encode symbols."""

    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:
        buf = getattr(sys.stdout, "buffer", None)
        if buf is None:
            raise
        buf.write(text.encode("utf-8", errors="replace"))
        buf.flush()


def _normalize_evaluate_format(raw: str) -> str:
    """Map evaluate ``--format`` aliases to ``human`` or ``json``."""

    f = raw.lower().strip()
    if f == "json":
        return "json"
    if f in {"human", "table", "compact", "detailed"}:
        return "human"
    raise InvalidInputError(
        "--format must be human or json (aliases: table, compact, detailed all map to human stdout layout)."
    )


def _normalize_profiles_format(raw: str) -> str:
    """Map profiles ``--format`` aliases to table/compact/detailed/json."""

    f = raw.lower().strip()
    if f == "human":
        return "compact"
    if f == "verbose":
        return "detailed"
    if f in {"detailed", "compact", "table", "json"}:
        return f
    raise InvalidInputError(
        "profiles --format must be one of: detailed, compact, table, json "
        "(aliases: human -> compact, verbose -> detailed)."
    )


def _normalize_recommend_format(raw: str) -> str:
    """Map recommend-profile ``--format`` aliases."""

    f = raw.lower().strip()
    if f in {"human", "table", "compact"}:
        return "human"
    if f == "json":
        return "json"
    raise InvalidInputError("recommend-profile --format must be human or json (aliases: table, compact map to human).")


_PROFILE_DISPLAY_ALIAS_TARGETS = dict(PROFILE_DIRECTORY_ALIASES)
_PROFILE_COMPACT_AUDIENCES = {
    "aws-level-1": "AWS teams starting honest checks.",
    "aws-level-2": "AWS teams with mature pipelines.",
    "aws-level-3": "AWS teams needing deterministic + evidence-backed hard gates.",
    "aws-release-hardening-1": "AWS teams preparing releases.",
    "aws-release-hardening-2": "AWS teams using evidence files.",
    "aws-release-hardening-3": "High-assurance AWS release teams.",
    "azure-level-1": "Azure teams starting OSS hygiene.",
    "azure-level-2": "Azure teams with stronger CI/CD.",
    "azure-level-3": "Security-focused Azure maintainers.",
    "azure-release-hardening-1": "Azure teams preparing releases.",
    "azure-release-hardening-2": "Azure teams with release governance.",
    "azure-release-hardening-3": "High-assurance Azure release teams.",
    "github-level-1": "GitHub maintainers starting a baseline.",
    "github-level-2": "GitHub maintainers with disciplined CI/CD.",
    "github-level-3": "Security-focused GitHub maintainers.",
    "github-aws-level-2": "Teams with GitHub SCM and AWS CI/CD.",
    "github-azure-level-2": "Teams with GitHub SCM and Azure Pipelines.",
    "github-release-hardening": "GitHub teams preparing releases.",
    "github-release-hardening-1": "GitHub teams preparing releases.",
    "github-release-hardening-2": "GitHub teams enforcing release posture.",
    "github-release-hardening-3": "High-assurance GitHub release teams.",
}
_PROFILE_COMPACT_DESCRIPTIONS = {
    "aws-level-1": "Starter AWS buildspec/pipeline signals (honest clone checks).",
    "aws-level-2": "Advisory AWS profile with validated pipeline exports + signals.",
    "aws-level-3": "Hard-gate AWS profile (evidence-backed posture, IAM, artifact SBOM/prov).",
    "aws-release-hardening-1": "AWS baseline plus pipeline/project evidence.",
    "aws-release-hardening-2": "Stricter AWS release posture with evidence.",
    "aws-release-hardening-3": "Level-3 hard gate plus release-time signal controls.",
    "azure-level-1": "Starter Azure DevOps baseline from repo signals.",
    "azure-level-2": "Stricter Azure pipeline governance baseline.",
    "azure-level-3": "High-assurance Azure DevOps governance baseline.",
    "azure-release-hardening-1": "Azure baseline plus branch/pipeline evidence.",
    "azure-release-hardening-2": "Stricter Azure release governance with evidence.",
    "azure-release-hardening-3": "Highest Azure release governance with evidence.",
    "github-level-1": "Starter GitHub baseline for clone-visible checks.",
    "github-level-2": "Stricter GitHub workflow hardening baseline.",
    "github-level-3": "High-assurance GitHub supply-chain baseline.",
    "github-aws-level-2": "Multi-platform advisory-only profile (GitHub + AWS signals).",
    "github-azure-level-2": "Multi-platform advisory-only profile (GitHub + Azure signals).",
    "github-release-hardening": "Legacy id — same as github-release-hardening-1 (prefer -1).",
    "github-release-hardening-1": "GitHub baseline plus release settings evidence.",
    "github-release-hardening-2": "Stricter GitHub release posture with evidence.",
    "github-release-hardening-3": "Highest GitHub release governance with evidence.",
}


@dataclass(frozen=True, slots=True)
class _ProfileDisplayRow:
    """Compact CLI metadata for a bundled profile."""

    profile_id: str
    title: str
    platform: str
    level: str
    controls: int
    track: str
    summary: str
    description: str
    audience: str
    is_legacy_alias: bool = False


def _profile_maturity_label(profile_id: str, *, is_legacy_alias: bool) -> str:
    """Human-oriented ladder label derived from bundled profile ids (no new profile schema)."""

    if is_legacy_alias:
        return "legacy bundled id (non-canonical)"
    if profile_id in {"github-aws-level-2", "github-azure-level-2"}:
        return "advisory hybrid (multi-platform)"
    if profile_id.endswith("release-hardening-3"):
        return "release hard-gate (extreme)"
    if "-level-3" in profile_id and "release-hardening" not in profile_id:
        return "hard-gate ladder (extreme)"
    if "release-hardening" in profile_id:
        return "release ladder"
    if "-level-2" in profile_id:
        return "advisory ladder"
    return "starter ladder"


def _profile_row_is_extreme(row: _ProfileDisplayRow) -> bool:
    m = _profile_maturity_label(row.profile_id, is_legacy_alias=row.is_legacy_alias).lower()
    pid = row.profile_id
    return (
        "extreme" in m
        or "hard-gate" in m
        or ("-level-3" in pid and "release-hardening" not in pid)
        or ("release-hardening-3" in pid)
    )


def _profile_row_is_advisory(row: _ProfileDisplayRow) -> bool:
    m = _profile_maturity_label(row.profile_id, is_legacy_alias=row.is_legacy_alias).lower()
    return "advisory" in m or "-level-2" in row.profile_id


def _profile_family_key(platform: str) -> str:
    return {"GitHub": "github", "Azure": "azure", "AWS": "aws", "Custom": "custom"}.get(platform, "custom")


def _profile_posture_descriptor(profile_id: str, maturity: str) -> str:
    ml = maturity.lower()
    if "legacy" in ml:
        return "legacy_alias"
    if "hybrid" in ml:
        return "multi_platform_advisory_hybrid"
    if "hard-gate" in ml or ("extreme" in ml and "advisory" not in ml):
        return "hard_gate_or_extreme"
    if "advisory" in ml:
        return "advisory"
    if "starter" in ml:
        return "starter"
    if "release" in ml:
        return "release_track"
    return "general"


def _profile_live_signal_posture(profile_id: str, posture_descriptor: str) -> str:
    if posture_descriptor == "multi_platform_advisory_hybrid":
        return "clone_visible_github_plus_platform_ci_signals_advisory"
    if posture_descriptor == "hard_gate_or_extreme":
        return "evidence_heavy_or_high_assurance_expectations"
    if "release-hardening" in profile_id:
        return "release_evidence_expectations"
    return "clone_visible_primary"


def _profile_recommended_gate(posture_descriptor: str) -> str:
    """Derived, rendering-only column. JSON profile-list schema is not affected."""

    return {
        "starter": "--fail-on fail",
        "advisory": "--fail-on none",
        "hard_gate_or_extreme": "--fail-on fail",
        "release_track": "--fail-on fail",
        "multi_platform_advisory_hybrid": "--fail-on none",
        "legacy_alias": "(migrate)",
    }.get(posture_descriptor, "--fail-on none")


def _filter_profile_display_rows(
    rows: list[_ProfileDisplayRow],
    *,
    family: str | None,
    only_extreme: bool,
    advisory_only: bool,
) -> list[_ProfileDisplayRow]:
    fam = family.strip().lower() if family else None
    if fam and fam not in {"github", "azure", "aws"}:
        raise InvalidInputError("--family must be one of: github, azure, aws.")
    want_platform = {"github": "GitHub", "azure": "Azure", "aws": "AWS"}.get(fam) if fam else None
    out: list[_ProfileDisplayRow] = []
    for row in rows:
        if want_platform is not None and row.platform != want_platform:
            continue
        if only_extreme and not _profile_row_is_extreme(row):
            continue
        if advisory_only and not _profile_row_is_advisory(row):
            continue
        out.append(row)
    return out


def _profile_assurance_mix(control_ids: tuple[str, ...], catalog: dict[str, ControlSpec]) -> dict[str, int]:
    """Count catalog assurance classes for controls listed in a bundled profile."""

    det = sig = evi = 0
    for cid in control_ids:
        spec = catalog.get(cid)
        if spec is None:
            continue
        if spec.assurance == "deterministic":
            det += 1
        elif spec.assurance == "signal":
            sig += 1
        elif spec.assurance == "evidence-backed":
            evi += 1
    return {"deterministic": det, "signal": sig, "evidence-backed": evi, "det": det, "sig": sig, "evi": evi}


def _profile_platform(profile_id: str) -> str:
    """Return the platform family for a profile id."""

    if profile_id.startswith("github-"):
        return "GitHub"
    if profile_id.startswith("azure-"):
        return "Azure"
    if profile_id.startswith("aws-"):
        return "AWS"
    return "Custom"


def _profile_level(profile_id: str) -> str:
    """Return the maturity level label for a profile id."""

    if "-level-" in profile_id:
        return f"L{profile_id.rsplit('-', 1)[-1]}"
    if profile_id.endswith("release-hardening"):
        return "L1"
    if "-release-hardening-" in profile_id:
        return f"L{profile_id.rsplit('-', 1)[-1]}"
    return "-"


def _profile_track(profile_id: str) -> str:
    """Return whether the profile is a baseline or release-hardening track."""

    return "rel" if "release-hardening" in profile_id else "base"


def _profile_summary(profile_id: str, description: str, title: str) -> str:
    """Return a short, scan-friendly CLI summary for a bundled profile."""

    level = _profile_level(profile_id)
    track = _profile_track(profile_id)
    summaries = {
        ("base", "L1"): "Core clone",
        ("base", "L2"): "Strict posture",
        ("base", "L3"): "High assurance",
        ("rel", "L1"): "Base + evidence",
        ("rel", "L2"): "Strict + evidence",
        ("rel", "L3"): "Assur. + evidence",
    }
    if (track, level) in summaries:
        return summaries[(track, level)]
    normalized = " ".join((description or title).split())
    if len(normalized) <= 48:
        return normalized
    return f"{normalized[:45].rstrip()}..."


def _compact_profile_description(profile_id: str, description: str) -> str:
    """Return a fixed executive description for the compact profiles table."""

    if profile_id in _PROFILE_COMPACT_DESCRIPTIONS:
        return _PROFILE_COMPACT_DESCRIPTIONS[profile_id]
    normalized = " ".join(description.split())
    return normalized if len(normalized) <= 48 else f"{normalized[:45].rstrip()}..."


def _compact_profile_audience(profile_id: str, audience: str) -> str:
    """Return a fixed executive audience for the compact profiles table."""

    if profile_id in _PROFILE_COMPACT_AUDIENCES:
        return _PROFILE_COMPACT_AUDIENCES[profile_id]
    normalized = " ".join(audience.split())
    return normalized if len(normalized) <= 40 else f"{normalized[:37].rstrip()}..."


def _iter_bundled_profiles() -> list[_ProfileDisplayRow]:
    """Return bundled profile metadata for display in the CLI."""

    root = merge_kit_root(None)
    profiles_dir = root / "profiles"
    available_profile_ids = {profile_yaml.parent.name for profile_yaml in profiles_dir.glob("*/profile.yaml")}
    rows: list[_ProfileDisplayRow] = []
    for profile_yaml in sorted(profiles_dir.glob("*/profile.yaml")):
        legacy_alias_target = _PROFILE_DISPLAY_ALIAS_TARGETS.get(profile_yaml.parent.name)
        if legacy_alias_target is not None and legacy_alias_target in available_profile_ids:
            continue
        profile = load_profile_by_id(root, profile_yaml.parent.name)
        title_clean = terminal_ui.sanitize_cli_display_text(profile.title)
        desc_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.description.split()))
        aud_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.audience.split()))
        rows.append(
            _ProfileDisplayRow(
                profile_id=profile.id,
                title=title_clean,
                platform=_profile_platform(profile.id),
                level=_profile_level(profile.id),
                controls=len(profile.control_ids),
                track=_profile_track(profile.id),
                summary=_profile_summary(profile.id, desc_clean, title_clean),
                description=desc_clean,
                audience=aud_clean,
                is_legacy_alias=False,
            )
        )
    seen = {r.profile_id for r in rows}
    for legacy_id in sorted(BUNDLED_PROFILE_LEGACY_IDS):
        if legacy_id in seen:
            continue
        profile = load_profile_by_id(root, legacy_id)
        title_clean = terminal_ui.sanitize_cli_display_text(profile.title)
        desc_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.description.split()))
        aud_clean = terminal_ui.sanitize_cli_display_text(" ".join(profile.audience.split()))
        rows.append(
            _ProfileDisplayRow(
                profile_id=profile.id,
                title=title_clean,
                platform=_profile_platform(profile.id),
                level=_profile_level(profile.id),
                controls=len(profile.control_ids),
                track=_profile_track(profile.id),
                summary=_profile_summary(profile.id, desc_clean, title_clean),
                description=desc_clean,
                audience=aud_clean,
                is_legacy_alias=True,
            )
        )
    plat_order = {"GitHub": 0, "Azure": 1, "AWS": 2, "Custom": 3}
    rows.sort(key=lambda r: (plat_order.get(r.platform, 9), int(r.is_legacy_alias), r.profile_id))
    return rows


def _print_profiles_table(
    *,
    detailed: bool,
    compact_layout: bool,
    rows: list[_ProfileDisplayRow] | None = None,
) -> None:
    """Render bundled profiles as a compact or detailed table on stdout."""

    plat_order = {"GitHub": 0, "Azure": 1, "AWS": 2, "Custom": 3}
    if rows is None:
        rows = _iter_bundled_profiles()
    rows = sorted(
        rows,
        key=lambda r: (plat_order.get(r.platform, 9), int(r.is_legacy_alias), r.profile_id),
    )
    longest_pid = max(
        (
            len(r.profile_id)
            + (len(" (legacy -> )") + len(PROFILE_DIRECTORY_ALIASES.get(r.profile_id, "")) if r.is_legacy_alias else 0)
            for r in rows
        ),
        default=16,
    )
    term_w = terminal_ui.terminal_width(sys.stdout)
    compact_default = compact_layout and not detailed
    if terminal_ui.human_tty_stdout():
        sub = "Six-column table follows" if not compact_default else None
        terminal_ui.print_profiles_catalog_panel(rows, subtitle=sub)
        if compact_default:
            oc = terminal_ui.build_stdout_console(width=term_w)
            oc.print(
                "[dim]Full table:[/dim] [cyan]profiles --format table[/cyan]  [dim]|[/dim]  "
                "[cyan]profiles --format detailed[/cyan]"
            )
            return
    layout = terminal_ui.profile_table_layout_for_width(
        terminal_columns=term_w,
        detailed=detailed,
        longest_profile_id_chars=longest_pid,
    )
    tbl_title = None if terminal_ui.human_tty_stdout() else "Bundled profiles"
    table = Table(title=tbl_title, show_lines=not (compact_layout and not detailed))
    table.add_column("Profile", style="cyan", no_wrap=True, max_width=layout.profile)
    table.add_column("Title", style="dim", max_width=layout.title, overflow="fold")
    table.add_column("Platform", style="dim", no_wrap=True, max_width=layout.platform)
    table.add_column("Level", style="dim", no_wrap=True, max_width=layout.level)
    table.add_column(
        "Recommended gate",
        style="default",
        header_style="dim",
        no_wrap=True,
        max_width=layout.gate,
    )
    table.add_column(
        "Audience",
        style="default",
        header_style="dim",
        max_width=layout.audience,
        overflow="fold",
    )
    table.add_column(
        "Description",
        style="default",
        header_style="dim",
        max_width=layout.description,
        overflow="fold",
    )

    for row in rows:
        pid = row.profile_id
        if row.is_legacy_alias:
            canon = PROFILE_DIRECTORY_ALIASES.get(row.profile_id, row.profile_id)
            pid = f"{row.profile_id} (legacy -> {canon})"
        maturity = _profile_maturity_label(row.profile_id, is_legacy_alias=row.is_legacy_alias)
        posture = _profile_posture_descriptor(row.profile_id, maturity)
        gate = _profile_recommended_gate(posture)
        table.add_row(
            pid,
            row.title,
            row.platform,
            row.level,
            gate,
            row.audience if detailed else _compact_profile_audience(row.profile_id, row.audience),
            row.description if detailed else _compact_profile_description(row.profile_id, row.description),
        )

    terminal_ui.build_stdout_console(width=term_w).print(table)


def _print_profiles_json(rows: list[_ProfileDisplayRow] | None = None) -> None:
    """Emit bundled profile metadata as JSON on stdout."""

    root = merge_kit_root(None)
    catalog = load_catalog(root / "controls" / "catalog.yaml")
    if rows is None:
        rows = _iter_bundled_profiles()
    profiles_out: list[dict[str, Any]] = []
    for r in rows:
        spec = load_profile_by_id(root, r.profile_id)
        mix = _profile_assurance_mix(spec.control_ids, catalog)
        maturity = _profile_maturity_label(r.profile_id, is_legacy_alias=r.is_legacy_alias)
        posture = _profile_posture_descriptor(r.profile_id, maturity)
        profiles_out.append(
            {
                "profile_id": r.profile_id,
                "canonical_profile_id": PROFILE_DIRECTORY_ALIASES.get(r.profile_id, r.profile_id),
                "is_legacy_alias": r.is_legacy_alias,
                "maturity_label": maturity,
                "family": _profile_family_key(r.platform),
                "posture": posture,
                "live_signal_posture": _profile_live_signal_posture(r.profile_id, posture),
                "assurance_mix": mix,
                "platform": r.platform,
                "level": r.level,
                "controls": r.controls,
                "track": r.track,
                "summary": r.summary,
            }
        )
    payload = {
        "schema_version": "oss-policy-kit/profile-list/v2",
        "kit_version": kit_version,
        "profiles": profiles_out,
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _write_wrapped_stdout_block(prefix: str, body: str, continuation: str) -> None:
    """Write ``body`` to stdout wrapped to ``terminal_width``, preserving ``prefix`` on first line."""

    tw = max(20, terminal_ui.terminal_width(sys.stdout))
    chunk = max(12, tw - len(prefix))
    parts = textwrap.wrap(body, width=chunk, break_long_words=True, break_on_hyphens=False)
    if not parts:
        return
    sys.stdout.write(f"{prefix}{parts[0]}\n")
    for ln in parts[1:]:
        sys.stdout.write(f"{continuation}{ln}\n")


def prepare_cli_args(args: list[str]) -> list[str]:
    """Normalize argv so a leading repository path dispatches to the `evaluate` subcommand.

    Click/Typer parses optional group-level positionals before subcommand names. A bare
    ``python -m oss_policy_kit ./repo --profile ...`` would otherwise steal ``evaluate`` as a
    positional. Inserting ``evaluate`` keeps shell, subprocess, and CliRunner behavior aligned
    when the first token is a path-like argument (not an option and not already ``evaluate``).
    """

    if not args:
        return args
    first = args[0]
    if first in {
        "evaluate",
        "profiles",
        "evaluate-many",
        "scaffold-evidence",
        "collect-evidence",
        "diff-reports",
        "recommend-profile",
    }:
        return args
    if first in ("--help", "-h", "--version", "-V"):
        return args
    if first.startswith("-"):
        return args
    return ["evaluate", *args]


def _print_operational_warning_summary(warnings: list[str]) -> None:
    """Surface a short warning summary on stderr without changing exit semantics."""

    if not warnings:
        return
    count = len(warnings)
    c = _stderr_console()
    c.print(f"[dim]Operational warnings ({count})[/dim] [dim]-- see Markdown/JSON reports[/dim]")
    for msg in warnings[:3]:
        wrapped = terminal_ui.human_wrap_lines(msg, stream=sys.stderr, subtract=4)
        lines = wrapped.split("\n")
        if not lines:
            continue
        c.print(f"[dim]-[/dim] [dim]{lines[0]}[/dim]")
        for cont in lines[1:]:
            c.print(f"[dim]  {cont}[/dim]")


def _execute_evaluate(
    target_pos: str | None,
    target_opt: str | None,
    profile: str,
    output_dir: Path,
    waivers: Path | None,
    scorecard_json: Path | None,
    kit_root: Path | None,
    *,
    output_format: str,
    summary_only: bool,
    fail_on: str,
    verbose: bool = False,
    quiet: bool = False,
    report_json_contract: str = "0.3",
) -> None:
    """Shared implementation for root-level and `evaluate` subcommand invocations."""

    try:
        fmt = _normalize_evaluate_format(output_format)
        policy = fail_on.lower()
        if policy not in {"none", "fail", "degraded"}:
            raise InvalidInputError("--fail-on must be one of: none, fail, degraded.")

        chosen = target_opt or target_pos
        if not chosen:
            raise InvalidInputError("Provide a repository path as TARGET or via --target/-t.")
        repo_root = resolve_existing_dir(chosen)
        root = merge_kit_root(kit_root)
        catalog_path = root / "controls" / "catalog.yaml"
        catalog = load_catalog(catalog_path)
        raw_profile = profile.strip()
        prof_path = Path(raw_profile)
        if raw_profile in BUNDLED_PROFILE_LEGACY_IDS and not (
            prof_path.is_file() and prof_path.suffix.lower() in {".yaml", ".yml"}
        ):
            canon = PROFILE_DIRECTORY_ALIASES.get(raw_profile, raw_profile)
            sys.stderr.write(
                f"DeprecationWarning: '{raw_profile}' is a legacy alias for '{canon}'.\n"
                f"It will be removed in a future major release. Migrate your CI to '{canon}'.\n"
            )
        prof = load_profile_by_id(root, profile)

        waiver_outcome = None
        if waivers is not None:
            wp = Path(waivers)
            if not wp.is_file():
                raise InvalidInputError(f"Waivers file not found: {wp}")
            waiver_outcome = parse_waivers_file(wp)

        scorecard = None
        if scorecard_json is not None:
            sp = Path(scorecard_json)
            if not sp.is_file():
                raise InvalidInputError(f"Scorecard file not found: {sp}")
            scorecard = load_scorecard_auto(sp)

        ext_waiver = str(Path(waivers).resolve()) if waivers is not None else None
        emit: Callable[[str], None] | None
        if verbose:
            _verbose_console = terminal_ui.build_stdout_console()

            def emit(line: str) -> None:
                with _verbose_console.capture() as _cap:
                    _verbose_console.print(line)
                _write_stdout_text(_cap.get())
        else:
            emit = None
        report = evaluate_repository(
            repo_root=repo_root,
            profile=prof,
            catalog=catalog,
            waiver_outcome=waiver_outcome,
            scorecard=scorecard,
            external_waiver_path=ext_waiver,
            verbose_emit=emit,
            report_json_contract=report_json_contract,
        )
        out = output_dir.resolve()
        json_path, md_path = write_reports(report, out)
        machine_stdout = fmt == "json"
        if not summary_only and not machine_stdout:
            _stderr_console().print(f"[green]Wrote[/green] {json_path}")
            _stderr_console().print(f"[green]Wrote[/green] {md_path}")
        warnings = report.operational_warnings
        if machine_stdout:
            # ``--summary-only --format json``: stdout is the only user-facing channel (pure JSON).
            if not summary_only:
                _stderr_console().print(f"[dim]Reports written to: {out}[/dim]")
                print_stdout_summary(report, output_format="json")
                if not quiet:
                    _print_operational_warning_summary(warnings)
            else:
                print_stdout_summary(report, output_format="json")
        elif summary_only:
            print_stdout_summary(report, output_format="human")
            if not quiet:
                _print_operational_warning_summary(warnings)
        else:
            if terminal_ui.human_tty_stdout():
                terminal_ui.print_evaluate_executive_preface(
                    report,
                    unicode_icons=terminal_ui.stream_supports_unicode(sys.stdout),
                )
            table = terminal_ui.render_eval_results_table(
                report,
                unicode_icons=terminal_ui.stream_supports_unicode(sys.stdout),
            )
            stdout_console = terminal_ui.build_stdout_console()
            with stdout_console.capture() as cap:
                stdout_console.print(table)
                status_str = "  ".join(f"{k}={v}" for k, v in sorted(report.summary_by_status.items()))
                stdout_console.print(
                    f"\n[dim]Summary: {status_str} | Controls: {len(report.results)} | Reports: {out}[/dim]"
                )
            _write_stdout_text(cap.get())
            if not quiet:
                _print_operational_warning_summary(warnings)
        if fail_on_violated(cast(FailOnPolicy, policy), report.summary_by_status):
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message
        _stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc


@app.callback(invoke_without_command=True)
def cli_root(
    ctx: Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show kit version and exit.",
        is_eager=True,
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help=(
            "Profile ID (e.g. github-level-1) or path to an external YAML profile (e.g. ./my-profile.yaml). "
            "External YAML required fields: id, title, controls (list of control IDs). "
            "Use the 'profiles' subcommand to list built-in options."
        ),
    ),
    show_profiles: bool = typer.Option(
        False,
        "--show-profiles",
        "-sp",
        help="Show bundled profiles with full audience and description details, and exit.",
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        help="Directory where evaluation-report.json and evaluation-report.md will be written.",
    ),
    waivers: Path | None = typer.Option(
        None,
        "--waivers",
        "-w",
        help="Optional waivers YAML file.",
    ),
    scorecard_json: Path | None = typer.Option(
        None,
        "--scorecard-json",
        "-sj",
        help="Optional OpenSSF Scorecard export used as supplemental evidence.",
    ),
    kit_root: Path | None = typer.Option(
        None,
        "--kit-root",
        "-k",
        help="Override the bundled controls/ and profiles/ directory.",
    ),
    target_opt: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Repository root to evaluate.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        "-f",
        help=(
            "Stdout summary format: human (default) or json. "
            "In json mode, a compact summary is written to stdout and file-write confirmations go to stderr. "
            "Aliases: table, compact, detailed -> human layout."
        ),
        case_sensitive=False,
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        "-so",
        help="Print only the summary on stdout.",
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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print per-control evaluation lines to stdout (dim), pipe-friendly.",
    ),
    report_json_contract: str = typer.Option(
        "0.3",
        "--report-json-contract",
        help="evaluation-report.json contract: 0.3 (default, gate summary), 0.2, or 0.1 (legacy).",
        case_sensitive=False,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress operational warning lines on stderr while keeping normal stdout output.",
    ),
) -> None:
    """Evaluate without typing `evaluate` (same flags as the subcommand)."""

    if version:
        typer.echo(kit_version)
        raise typer.Exit(0)
    if show_profiles:
        try:
            _print_profiles_table(detailed=True, compact_layout=False)
        except LoadError as exc:
            _stderr_console().print(f"[red]Error:[/red] {exc.message}")
            raise typer.Exit(code=2) from exc
        raise typer.Exit(0)
    if ctx.invoked_subcommand is not None:
        return
    if profile is None:
        err = (
            "--profile is required when running without the `evaluate` subcommand "
            "(for example: `python -m oss_policy_kit --target . --profile github-level-1`)."
        )
        wrapped = terminal_ui.human_wrap_lines(err, stream=sys.stderr, subtract=10)
        wlines = wrapped.split("\n")
        _stderr_console().print(f"[red]Error:[/red] {wlines[0]}")
        for ln in wlines[1:]:
            _stderr_console().print(ln)
        raise typer.Exit(code=2)
    _execute_evaluate(
        target_pos=None,
        target_opt=target_opt,
        profile=profile,
        output_dir=output_dir,
        waivers=waivers,
        scorecard_json=scorecard_json,
        kit_root=kit_root,
        output_format=output_format.lower(),
        summary_only=summary_only,
        fail_on=fail_on.lower(),
        verbose=verbose,
        quiet=quiet,
        report_json_contract=report_json_contract.strip().lower().removeprefix("v"),
    )


@app.command("profiles")
def profiles_cmd(
    output_format: str = typer.Option(
        "compact",
        "--format",
        "-f",
        help=(
            "compact (default): dense table; table: full grid lines; detailed: full YAML audience/description; "
            "json. Aliases: human -> compact, verbose -> detailed."
        ),
        case_sensitive=False,
    ),
    family: str | None = typer.Option(
        None,
        "--family",
        help="Restrict listing to one platform family: github, azure, or aws.",
    ),
    only_extreme: bool = typer.Option(
        False,
        "--only-extreme",
        help="Only profiles with extreme / hard-gate posture (level-3 or release-hardening-3).",
    ),
    advisory_only: bool = typer.Option(
        False,
        "--advisory-only",
        help="Only advisory-tier profiles (includes level-2 ladders and hybrid advisories).",
    ),
) -> None:
    """List bundled profiles available in this kit build."""

    try:
        fmt = _normalize_profiles_format(output_format)
        filtered = _filter_profile_display_rows(
            _iter_bundled_profiles(),
            family=family,
            only_extreme=only_extreme,
            advisory_only=advisory_only,
        )
        if fmt == "json":
            _print_profiles_json(filtered)
        else:
            if fmt == "detailed":
                _print_profiles_table(detailed=True, compact_layout=False, rows=filtered)
            elif fmt == "compact":
                _print_profiles_table(detailed=False, compact_layout=True, rows=filtered)
            else:
                # fmt == "table": full grid lines, default column balance (not density-compact).
                _print_profiles_table(detailed=False, compact_layout=False, rows=filtered)
    except LoadError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except OssPolicyKitError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc


@app.command("evaluate", epilog=_EVALUATE_EPILOG)
def evaluate_cmd(
    target_pos: str | None = typer.Argument(
        default=None,
        help="Repository root. Prefer --target/-t if the path contains spaces.",
    ),
    profile: str = typer.Option(
        ...,
        "--profile",
        "-p",
        help=(
            "Profile ID (e.g. github-level-1) or path to an external YAML profile (e.g. ./my-profile.yaml). "
            "External YAML required fields: id, title, controls (list of control IDs). "
            "Use the 'profiles' subcommand to list built-in options."
        ),
    ),
    output_dir: Path = typer.Option(
        Path("out"),
        "--output-dir",
        "-o",
        help="Directory where evaluation-report.json and evaluation-report.md will be written.",
    ),
    waivers: Path | None = typer.Option(
        None,
        "--waivers",
        "-w",
        help="Optional waivers YAML file.",
    ),
    scorecard_json: Path | None = typer.Option(
        None,
        "--scorecard-json",
        "-sj",
        help="Optional OpenSSF Scorecard export used as supplemental evidence.",
    ),
    kit_root: Path | None = typer.Option(
        None,
        "--kit-root",
        "-k",
        help="Override the bundled controls/ and profiles/ directory.",
    ),
    target_opt: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Repository root to evaluate.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        "-f",
        help=(
            "Stdout summary format: human (default) or json. "
            "In json mode, stdout is JSON only; where files were written is repeated on stderr. "
            "Aliases: table, compact, detailed -> human layout."
        ),
        case_sensitive=False,
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        "-so",
        help="Print only the summary on stdout.",
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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Print per-control evaluation lines to stdout (dim); json mode unchanged.",
    ),
    report_json_contract: str = typer.Option(
        "0.3",
        "--report-json-contract",
        help="evaluation-report.json contract: 0.3 (default, gate summary), 0.2, or 0.1 (legacy).",
        case_sensitive=False,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress operational warning lines on stderr while keeping normal stdout output.",
    ),
) -> None:
    """Evaluate a local repository clone against a bundled profile.

    Use this command when you want a full evaluation report written to disk.

    Preferred form:
      python -m oss_policy_kit evaluate --target <repo> --profile <profile>

    You can also pass the repository path positionally:
      python -m oss_policy_kit evaluate <repo> --profile <profile>

    Outputs:
      - evaluation-report.json
      - evaluation-report.md
    """

    _execute_evaluate(
        target_pos=target_pos,
        target_opt=target_opt,
        profile=profile,
        output_dir=output_dir,
        waivers=waivers,
        scorecard_json=scorecard_json,
        kit_root=kit_root,
        output_format=output_format,
        summary_only=summary_only,
        fail_on=fail_on,
        verbose=verbose,
        quiet=quiet,
        report_json_contract=report_json_contract.strip().lower().removeprefix("v"),
    )


_EVALUATE_MANY_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Evaluate each child folder as a repo:",
        "  python -m oss_policy_kit evaluate-many --target-root ./repos --profiles github-level-1",
        "CI gate across the batch (exit 1 if any repo has fail):",
        "  python -m oss_policy_kit evaluate-many --target-root ./repos --profiles github-level-1 --fail-on fail",
        "Skip folders that look like docs/assets (non-repos):",
        "  python -m oss_policy_kit evaluate-many --target-root ./mono --profiles github-level-1 --skip-non-repos",
        "",
        "----------------------------------------------------------------------",
        "EXIT CODES",
        "----------------------------------------------------------------------",
        "  0  Batch finished; fail-on threshold not violated (when --fail-on applies).",
        "  1  Batch finished; fail-on threshold violated.",
        "  2  Invalid usage, missing input, or validation/load error.",
        "  3  Unexpected internal error.",
        "",
        "----------------------------------------------------------------------",
        "TIPS",
        "----------------------------------------------------------------------",
        "Use --skip-non-repos or --include/--exclude to avoid evaluating non-repository directories.",
    ]
)


@app.command("evaluate-many", epilog=_EVALUATE_MANY_EPILOG)
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
            "azure-pipelines.yml, buildspec.yml), or a Dockerfile. "
            "README.md alone is NOT sufficient."
        ),
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress incremental stderr progress lines; keep final batch summary writes.",
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
            cons = _stderr_console()

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
        )
        _stderr_console().print(f"[green]Wrote[/green] {batch.batch_json.resolve()}")
        _stderr_console().print(f"[green]Wrote[/green] {batch.batch_md.resolve()}")
        if not quiet:
            _warn_if_batch_skipped_directories(batch.batch_json)
        if batch.gate_violated:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        _stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc


@app.command("scaffold-evidence")
def scaffold_evidence_cmd(
    target: str = typer.Option(..., "--target", "-t", help="Repository root where .oss-policy-kit/ will be created."),
    platform: str = typer.Option(
        ...,
        "--platform",
        help="github, azure, or aws -- selects which evidence JSON templates to emit.",
        case_sensitive=False,
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing evidence files and README (default: skip existing files).",
    ),
) -> None:
    """Create `.oss-policy-kit/evidence/` with schema-shaped JSON templates for release-hardening workflows.

    Manual evidence mode: generates template JSON files that must be filled in by hand.
    For automatic evidence collection via platform APIs, use ``collect-evidence`` instead.
    """

    try:
        repo = resolve_existing_dir(target)
        outcome = scaffold_evidence_files(repo, platform, force=force)
        sys.stdout.write("scaffold-evidence summary:\n")
        sys.stdout.write(f"  created: {len(outcome.created)}\n")
        sys.stdout.write(f"  skipped (existing): {len(outcome.skipped)}\n")
        sys.stdout.write(f"  overwritten: {len(outcome.overwritten)}\n")
        for p in outcome.created:
            _write_wrapped_stdout_block("  + ", str(p.resolve()), "    ")
        for p in outcome.skipped:
            _write_wrapped_stdout_block("  = ", f"{p.resolve()} (unchanged)", "    ")
        for p in outcome.overwritten:
            _write_wrapped_stdout_block("  ! ", f"{p.resolve()} (replaced)", "    ")
        if not force and outcome.skipped:
            sys.stdout.write("  (re-run with --force to replace existing files)\n")
        tail = (
            "Manual mode: replace placeholders before relying on results. "
            "For API-backed evidence, use collect-evidence. "
            "Existing files were preserved unless --force was set."
        )
        wrapped = terminal_ui.human_wrap_lines(tail, stream=sys.stderr, subtract=2)
        lines = wrapped.split("\n")
        _stderr_console().print(f"[green]Scaffold complete.[/green] {lines[0]}")
        for ln in lines[1:]:
            _stderr_console().print(ln)
    except OssPolicyKitError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc


_COLLECT_PREVIEW: dict[str, list[tuple[str, str]]] = {
    "github": [
        ("branch-protection.json", "GET /repos/{owner}/{repo}/branches/{default}/protection"),
        ("github-rulesets.json", "GET /repos/{owner}/{repo}/rulesets"),
        ("github-secret-scanning.json", "GET /repos/{owner}/{repo} (security_and_analysis)"),
        ("github-environment-protection.json", "GET /repos/{owner}/{repo}/environments"),
    ],
    "azure": [
        ("azure-branch-policies.json", "GET /{org}/{project}/_apis/policy/configurations?api-version=7.1"),
        ("azure-pipeline-governance.json", "GET /{org}/{project}/_apis/pipelines?api-version=7.1"),
    ],
    "aws": [
        ("aws-codebuild-project.json", "codebuild.batch_get_projects (when AWS_CODEBUILD_PROJECT is set)"),
        ("aws-codepipeline.json", "codepipeline.get_pipeline (when AWS_CODEPIPELINE_NAME is set)"),
        ("aws-codecommit-review-posture.json", "codecommit APIs (when --repo is a CodeCommit repository name)"),
    ],
}

_COLLECT_REQUIRED_ENV: dict[str, list[str]] = {
    "github": ["GITHUB_TOKEN"],
    "azure": ["AZURE_DEVOPS_ORG", "AZURE_DEVOPS_TOKEN"],
    "aws": ["AWS credential chain (boto3)", "AWS_CODEBUILD_PROJECT and/or AWS_CODEPIPELINE_NAME optional"],
}

# Environment variables whose presence (not their secret value) is reported in the dry-run preview so
# operators can confirm their local shell is ready before committing to a live collection.
_COLLECT_ENV_PROBES: dict[str, tuple[str, ...]] = {
    "github": ("GITHUB_TOKEN",),
    "azure": ("AZURE_DEVOPS_ORG", "AZURE_DEVOPS_TOKEN"),
    "aws": (
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_CODEBUILD_PROJECT",
        "AWS_CODEPIPELINE_NAME",
    ),
}


def _env_probe_status(name: str) -> str:
    """Return ``set`` / ``not set`` for *name* without ever echoing the variable value."""

    raw = os.environ.get(name)
    return "set" if raw is not None and raw.strip() else "not set"


def _print_collect_dry_run_preview(
    *,
    target: Path,
    platform: str,
    repo_slug: str | None,
    output_dir: Path | None,
) -> None:
    """Print what ``collect-evidence`` would collect without API calls or credentials.

    Never prints secret values; only whether each known credential-related variable is populated.
    """

    out = (output_dir or (target / ".oss-policy-kit" / "evidence")).resolve()
    detected_slug: str | None = None
    if repo_slug is None and platform == "github":
        detected_slug = read_github_repo_slug_from_git_config(target)
    effective_slug = (repo_slug or "").strip() or detected_slug
    console = terminal_ui.build_stdout_console()
    console.print(f"\n[bold cyan]collect-evidence dry-run[/bold cyan] -- platform: [bold]{platform}[/bold]")
    console.print(f"  Target:     {target.resolve()}")
    console.print(f"  Output dir: {out}")
    slug_display = effective_slug if effective_slug else "[not detected -- pass --repo where needed]"
    console.print(f"  Repo slug:  {slug_display}")
    env_vars = _COLLECT_REQUIRED_ENV.get(platform, [])
    console.print(f"  Credentials (needed without --dry-run): {', '.join(env_vars)}")
    probes = _COLLECT_ENV_PROBES.get(platform, ())
    if probes:
        console.print("  Environment probe (values are not printed):")
        for name in probes:
            console.print(f"    - {name}: {_env_probe_status(name)}")
    entries = _COLLECT_PREVIEW.get(platform, [])
    if entries:
        console.print("\n[bold]Would create:[/bold]")
        for fname, endpoint in entries:
            console.print(f"  [green]+[/green] {out / fname}")
            console.print(f"    [dim]via {endpoint}[/dim]")
    console.print("\n[dim]Run without --dry-run to execute (credentials required).[/dim]")


@app.command("collect-evidence")
def collect_evidence_cmd(
    target: Path = typer.Option(..., "--target", "-t", help="Repository root path."),
    platform: str = typer.Option(
        ...,
        "--platform",
        help="Platform: github, azure, or aws (each requires the matching credentials; see command help).",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory to write evidence files. Defaults to <target>/.oss-policy-kit/evidence/.",
    ),
    repo_slug: str | None = typer.Option(
        None,
        "--repo",
        help=(
            "Repository slug: GitHub ``org/repo``; Azure DevOps ``ProjectName/repoName``; "
            "AWS CodeCommit repository name (optional if only AWS_CODEBUILD_PROJECT / AWS_CODEPIPELINE_NAME are set)."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview files and API surface without calling platforms or requiring credentials.",
    ),
) -> None:
    """Collect platform evidence files automatically via API.

    Writes the same JSON evidence files that scaffold-evidence creates as templates,
    but populated with real data from the platform API.
    """

    try:
        plat = platform.strip().lower()
        repo = resolve_existing_dir(str(target))
        if dry_run:
            _print_collect_dry_run_preview(
                target=repo,
                platform=plat,
                repo_slug=repo_slug,
                output_dir=output_dir,
            )
            return

        collector: GitHubEvidenceCollector | AzureDevOpsEvidenceCollector | AWSEvidenceCollector
        slug: str

        if plat == "github":
            token = os.environ.get("GITHUB_TOKEN", "").strip()
            if not token:
                raise OSError(
                    "GITHUB_TOKEN is not set. Export a token with permission to read the repository "
                    "(and security analysis where applicable)."
                )
            slug = (repo_slug or "").strip() or read_github_repo_slug_from_git_config(repo) or ""
            if not slug:
                raise InvalidInputError(
                    "Could not determine GitHub repo slug; pass --repo org/repo or add an origin remote "
                    "pointing to GitHub."
                )
            collector = GitHubEvidenceCollector(token)
        elif plat == "azure":
            org = os.environ.get("AZURE_DEVOPS_ORG", "").strip()
            pat = os.environ.get("AZURE_DEVOPS_TOKEN", "").strip()
            if not org or not pat:
                raise OSError(
                    "AZURE_DEVOPS_ORG and AZURE_DEVOPS_TOKEN must be set for Azure DevOps collection "
                    "(PAT with Code, Build, and Project read access)."
                )
            slug = (repo_slug or "").strip()
            if not slug:
                raise InvalidInputError(
                    "Azure DevOps requires --repo ProjectName/repoName (no automatic slug detection yet)."
                )
            collector = AzureDevOpsEvidenceCollector(organization=org, personal_access_token=pat)
        elif plat == "aws":
            build_n = os.environ.get("AWS_CODEBUILD_PROJECT", "").strip()
            pipe_n = os.environ.get("AWS_CODEPIPELINE_NAME", "").strip()
            slug = (repo_slug or "").strip()
            if not slug and not build_n and not pipe_n:
                raise InvalidInputError(
                    "For AWS, pass --repo with your CodeCommit repository name and/or set "
                    "AWS_CODEBUILD_PROJECT and/or AWS_CODEPIPELINE_NAME in the environment."
                )
            collector = AWSEvidenceCollector()
        else:
            raise InvalidInputError(f"Unsupported --platform {platform!r}; use github, azure, or aws.")

        try:
            rows = collector.collect(slug)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from exc

        table = Table(title=f"collect-evidence ({plat})", show_lines=True)
        table.add_column("Evidence file", style="cyan", no_wrap=True)
        table.add_column("Source", style="dim")
        dest = (output_dir or (repo / ".oss-policy-kit" / "evidence")).resolve()
        dest.mkdir(parents=True, exist_ok=True)
        for row in rows:
            out_path = dest / f"{row.evidence_key}.json"
            out_path.write_text(json.dumps(row.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            table.add_row(str(out_path.name), row.source_url)
        _stderr_console().print(table)
        _stderr_console().print(f"[green]Wrote[/green] {len(rows)} file(s) under {dest}")
    except OSError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except OssPolicyKitError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        _stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc


_DIFF_REPORTS_EPILOG = "\n\n".join(
    [
        "----------------------------------------------------------------------",
        "EXAMPLES",
        "----------------------------------------------------------------------",
        "Default CI gate (exit 1 when any control regresses):",
        "  python -m oss_policy_kit diff-reports --before old.json --after new.json",
        "Opt out of the regression gate (always exit 0 unless the inputs are invalid):",
        "  python -m oss_policy_kit diff-reports --before old.json --after new.json --no-fail-on-regression",
        "Markdown drift report on stdout for a PR comment:",
        "  python -m oss_policy_kit diff-reports --before old.json --after new.json --format markdown",
        "",
        "Note: the gate flag pair is --fail-on-regression / --no-fail-on-regression (singular).",
    ]
)


@app.command("diff-reports", epilog=_DIFF_REPORTS_EPILOG)
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
) -> None:
    """Compare two evaluation reports and show posture drift."""

    try:
        if not before.is_file():
            raise InvalidInputError(f"--before not found: {before}")
        if not after.is_file():
            raise InvalidInputError(f"--after not found: {after}")
        b = load_report_json(before)
        a = load_report_json(after)
        drift = compute_drift(b, a)
        if drift.profile_mismatch:
            _stderr_console().print(
                "[yellow]Warning:[/yellow] profiles differ "
                f"([cyan]{drift.before_profile_id}[/cyan] → [cyan]{drift.after_profile_id}[/cyan]). "
                "Controls listed under 'New in after' or 'Removed from after' may reflect "
                "a profile scope change rather than a posture change."
            )
        text = render_drift_report(drift, fmt, color=terminal_ui.human_tty_stdout())
        _write_stdout_text(text)
        if drift.has_regressions and fail_on_regression:
            raise typer.Exit(code=1)
    except OssPolicyKitError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except ValueError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # noqa: BLE001
        _stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc


@app.command("recommend-profile")
def recommend_profile_cmd(
    target: str = typer.Option(..., "--target", "-t", help="Repository root to inspect for CI platform signals."),
    output_format: str = typer.Option(
        "human",
        "--format",
        "-f",
        help="human (default) or json on stdout; aliases table, compact -> human.",
        case_sensitive=False,
    ),
) -> None:
    """Suggest starter profiles from repository layout (heuristic; not a compliance decision)."""

    try:
        fmt = _normalize_recommend_format(output_format)
        repo = resolve_existing_dir(target)
        rec = build_profile_recommendation(repo)
        if fmt == "json":
            sys.stdout.write(json.dumps(rec.to_json_dict(), ensure_ascii=False, indent=2) + "\n")
        elif terminal_ui.human_tty_stdout():
            terminal_ui.print_recommend_profile_human_rich(rec, repo_root=repo)
        else:
            sys.stdout.write("Profile suggestions (heuristic, not a compliance decision):\n")
            for s in rec.suggestions:
                pid = s["profile_id"]
                why = s["rationale"]
                sys.stdout.write(f"  {pid}\n")
                _write_wrapped_stdout_block("    -> ", why, "       ")
            if rec.signals_detected:
                sys.stdout.write("\nObserved signals:\n")
                for sig in rec.signals_detected:
                    prefix = f"  - [{sig['id']}] "
                    _write_wrapped_stdout_block(prefix, str(sig["detail"]), " " * len(prefix))
            if rec.notes:
                sys.stdout.write("\nNotes:\n")
                for note in rec.notes:
                    _write_wrapped_stdout_block("  - ", str(note), "    ")
    except OssPolicyKitError as exc:
        _stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            with suppress(Exception):
                stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) > 1:
        sys.argv[1:] = prepare_cli_args(list(sys.argv[1:]))
    app()


if __name__ == "__main__":
    main()
