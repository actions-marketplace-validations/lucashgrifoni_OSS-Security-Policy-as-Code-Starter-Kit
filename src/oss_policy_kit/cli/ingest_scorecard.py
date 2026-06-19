"""``oss-policy-kit ingest-scorecard`` subcommand (T2.3).

The read-only consumer for an OpenSSF Scorecard v5.x JSON result. It loads a
``scorecard --format json`` export, maps each Scorecard check to the kit control it
**corroborates**, and reports the mapping plus the result's freshness. A Scorecard result
is supplemental, inferred-trust signal: matched controls are corroborated, never elevated
in assurance grade (see ``docs/signal-controls-audit.md``).

The crosswalk + freshness logic lives in
:mod:`oss_policy_kit.application.scorecard_ingest` (the single source of truth); this
module only resolves the input file, shapes the report, and renders it.

This subcommand intentionally does **not** recompute or re-derive any Scorecard check
(the kit is not a scanner engine — it records Scorecard's own verdicts verbatim) and
does **not** change any ``evaluate`` gate (symmetric with ``ingest-insights``). See
``docs/scorecard-mapping.md``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit.application.scorecard_ingest import (
    EVIDENCE_MAX_AGE_DAYS,
    ScorecardIngestReport,
    ingest_scorecard,
)
from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError

_TOOL_NAME = "oss-policy-kit ingest-scorecard"
_DISCOVERY_CANDIDATES: tuple[str, ...] = (
    ".oss-policy-kit/evidence/scorecard-result.json",
    ".oss-policy-kit/evidence/scorecard.json",
    "scorecard-result.json",
    "scorecard.json",
)


def _discover(target: Path) -> Path | None:
    for rel in _DISCOVERY_CANDIDATES:
        candidate = target / rel
        if candidate.is_file():
            return candidate
    return None


def _resolve_input(target: Path, input_path: Path | None) -> Path | None:
    if input_path is None:
        return _discover(target)
    chosen = input_path if input_path.is_absolute() else target / input_path
    if not chosen.is_file():
        raise InvalidInputError(f"--input {chosen} is not a file.")
    return chosen


def _not_found_payload(target: Path) -> dict[str, Any]:
    return {
        "tool": _TOOL_NAME,
        "found": False,
        "searched_root": str(target),
        "input_path": None,
        "result_date": None,
        "freshness": "n/a",
        "aggregate_score": None,
        "corroborated_controls": [],
        "mapped_checks": [],
    }


def _render_not_found(target: Path) -> None:
    lines = [
        "OpenSSF Scorecard - none found",
        f"  Searched under: {target}",
        "  No scorecard-result.json found (e.g. scorecard --format json > "
        ".oss-policy-kit/evidence/scorecard-result.json), or pass --input.",
    ]
    write_stdout_text("\n".join(lines) + "\n")


def _render_human(report: ScorecardIngestReport) -> None:
    score = f"{report.aggregate_score:.1f}/10" if report.aggregate_score is not None else "(not reported)"
    lines = [
        "OpenSSF Scorecard - ingested (composed as evidence; verdicts recorded verbatim)",
        f"  File: {report.input_path}",
        f"  Aggregate score: {score}",
        f"  Result date: {report.result_date or '(undated)'}  [{report.freshness}]",
        "",
        "  Mapped checks (Scorecard check -> kit control it corroborates; score is Scorecard's own, verbatim):",
    ]
    for m in report.mapped:
        if m.present:
            sc = m.score if m.score is not None else "n/a"
            lines.append(f"    - {m.scorecard_check:<24} score={sc!s:<4} -> {m.control_id}  ({m.note})")
        else:
            lines.append(f"    - {m.scorecard_check:<24} (not in result)  -> {m.control_id}")
    lines.append("")
    corroborated = report.corroborated_controls
    if corroborated:
        lines.append(
            f"  Corroborated by this fresh result (supplemental inferred-trust signal) "
            f"for {len(corroborated)} control(s): " + ", ".join(corroborated)
        )
    elif report.freshness == "stale":
        lines.append(
            f"  Result is STALE (> {EVIDENCE_MAX_AGE_DAYS}d) - not counted as current corroboration; "
            "refresh the Scorecard run."
        )
    else:
        lines.append("  No mapped checks present (or result undated) - nothing corroborated.")
    lines.append("")
    lines.append(
        "  Note: read-only, inferred-trust. ingest-scorecard records Scorecard's own results and maps them "
        "to controls; it never elevates a control's assurance grade, never recomputes a check, and changes "
        "no `evaluate` gate."
    )
    write_stdout_text("\n".join(lines) + "\n")


def _run_ingest_scorecard(target: Path, input_path: Path | None, output_format: str) -> None:
    fmt = output_format.lower().strip()
    if fmt not in {"human", "json"}:
        raise InvalidInputError("--format must be human or json.")
    target_path = target.resolve()
    if not target_path.is_dir():
        raise InvalidInputError(f"--target {target_path} is not a directory.")

    chosen = _resolve_input(target_path, input_path)
    if chosen is None:
        if fmt == "json":
            write_stdout_text(json.dumps(_not_found_payload(target_path), indent=2, sort_keys=True) + "\n")
        else:
            _render_not_found(target_path)
        return

    try:
        report = ingest_scorecard(chosen, now=datetime.now(UTC))
    except Exception as exc:  # noqa: BLE001 - a file that exists but cannot be parsed is an honest exit 1
        msg = f"Scorecard result {chosen.name} could not be parsed: {exc}"
        if fmt == "json":
            payload = _not_found_payload(target_path)
            payload["found"] = True
            payload["input_path"] = str(chosen)
            payload["error"] = msg
            write_stdout_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        else:
            write_stdout_text(f"OpenSSF Scorecard - INVALID\n  File: {chosen}\n  ERROR: {msg}\n")
        raise typer.Exit(code=1) from exc

    if fmt == "json":
        payload = report.to_dict()
        payload["tool"] = _TOOL_NAME
        write_stdout_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        _render_human(report)


@app.command("ingest-scorecard", rich_help_panel=CMD_PANEL_EXPORT)
def ingest_scorecard_cmd(
    target: Path = typer.Option(
        Path("."),
        "--target",
        help="Repository to inspect for a Scorecard result. Defaults to current directory.",
    ),
    input_path: Path | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Explicit path to a Scorecard JSON result. Overrides auto-discovery under --target.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help="Output format: human (default) or json.",
    ),
) -> None:
    """Ingest an OpenSSF Scorecard v5.x JSON result and map it to kit controls (read-only).

    Loads a ``scorecard --format json`` result (auto-discovered under ``--target`` at
    ``.oss-policy-kit/evidence/scorecard-result.json``, or via ``--input``), maps each
    Scorecard check to the kit control it corroborates, and reports the mapping +
    freshness. The corroboration is supplemental inferred-trust signal (never elevates a
    control's assurance grade). Records Scorecard's own scores verbatim; never recomputes a
    check and changes no ``evaluate`` verdict. See docs/scorecard-mapping.md.

    Exit codes: 0 found-and-parsed or not-found (informational); 1 found-but-unparseable;
    2 usage error; 3 unexpected internal error.
    """

    try:
        _run_ingest_scorecard(target, input_path, output_format)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message, no traceback leak
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
