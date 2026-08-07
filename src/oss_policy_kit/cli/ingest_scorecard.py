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

from oss_policy_kit.adapters.scorecard_json import ScorecardBundle, load_scorecard_auto
from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES, oversize_reason
from oss_policy_kit.application.scorecard_ingest import (
    EVIDENCE_MAX_AGE_DAYS,
    ScorecardIngestReport,
    build_report,
)
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
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
        # Echo the user-supplied string, never the resolved candidate: joining a
        # relative --input onto the resolved --target produces an absolute path that
        # leaks the auditor's home directory / OS username (M-002). Mirrors
        # ``export-evidence --report``.
        raise InvalidInputError(f"--input {input_path} is not a file.")
    return chosen


def _display_path(chosen: Path, root: Path, typed: Path | None) -> str:
    """The path to print and to record in the JSON report — never an absolute one (M-002).

    Echoes the ``--input`` string the user typed while it is relative; otherwise cites the
    file's location relative to ``--target``, falling back to the bare name for a file
    outside the target tree.
    """

    if typed is not None and not typed.is_absolute():
        return typed.as_posix()
    try:
        return chosen.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return chosen.name


def _not_found_payload(searched: str) -> dict[str, Any]:
    """Not-found payload; *searched* is the ``--target`` string the user typed (M-002)."""

    return {
        "tool": _TOOL_NAME,
        "found": False,
        "searched_root": searched,
        "input_path": None,
        "result_date": None,
        "freshness": "n/a",
        "aggregate_score": None,
        "corroborated_controls": [],
        "mapped_checks": [],
    }


def _render_not_found(searched: str) -> None:
    lines = [
        "OpenSSF Scorecard - none found",
        f"  Searched under: {searched}",
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


def _unrecognized_scorecard_reason(bundle: ScorecardBundle, name: str) -> str | None:
    """Refuse a document that parsed but carries nothing of a Scorecard result.

    Any JSON the reader could not recognise degrades field by field — unknown keys yield
    no checks, no aggregate score, no date — so an arbitrary document was announced as
    "OpenSSF Scorecard - ingested", with "Aggregate score: (not reported)", "Result date:
    (undated)" and every mapped check "(not in result)", and exit 0. Nothing had been
    ingested; the headline said otherwise.

    The test is deliberately the whole-document one: a real ``scorecard --format json``
    export always carries ``date`` and ``score``, and any one check, score or date is
    enough to keep the lenient reporting for a partial or hand-trimmed export. Only a file
    with none of the three — the exact "everything empty" state — is refused.
    """

    if bundle.checks or bundle.aggregate_score is not None or bundle.result_date is not None:
        return None
    return (
        f"Scorecard result {name} is not an OpenSSF Scorecard result: it carries no checks, "
        "no aggregate score and no result date. Produce one with "
        "'scorecard --repo <url> --format json'."
    )


def _render_invalid(msg: str, display: str, searched: str, fmt: str) -> None:
    """Report a found-but-unusable result, in whichever format was requested."""

    if fmt == "json":
        payload = _not_found_payload(searched)
        payload["found"] = True
        payload["input_path"] = display
        payload["error"] = msg
        write_stdout_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        write_stdout_text(f"OpenSSF Scorecard - INVALID\n  File: {display}\n  ERROR: {msg}\n")


def _run_ingest_scorecard(target: Path, input_path: Path | None, output_format: str) -> None:
    fmt = output_format.lower().strip()
    if fmt not in {"human", "json"}:
        raise InvalidInputError("--format must be human or json.")
    target_path = target.resolve()
    if not target_path.is_dir():
        # Echo the user-supplied string, never target.resolve(): the absolute
        # path leaks the auditor's home directory / username (M-002).
        raise InvalidInputError(f"--target {target} is not a directory.")

    # The JSON report is shareable; cite the typed --target, not its resolved form (M-002).
    searched = str(target)
    chosen = _resolve_input(target_path, input_path)
    if chosen is None:
        if fmt == "json":
            write_stdout_text(json.dumps(_not_found_payload(searched), indent=2, sort_keys=True) + "\n")
        else:
            _render_not_found(searched)
        return

    r = oversize_reason(chosen, MAX_EVIDENCE_BYTES, label="Scorecard JSON")
    if r:
        raise InvalidInputError(r)

    display = _display_path(chosen, target_path, input_path)
    try:
        bundle = load_scorecard_auto(chosen)
    except Exception as exc:  # noqa: BLE001 - a file that exists but cannot be parsed is an honest exit 1
        _render_invalid(f"Scorecard result {chosen.name} could not be parsed: {exc}", display, searched, fmt)
        raise typer.Exit(code=1) from exc

    unusable = _unrecognized_scorecard_reason(bundle, chosen.name)
    if unusable is not None:
        _render_invalid(unusable, display, searched, fmt)
        raise typer.Exit(code=1)

    # ``input_path`` is the display form from the start: the loaded bundle knows only the
    # absolute path it was handed, and neither the "File:" line nor the JSON report may
    # carry it (M-002).
    report = build_report(bundle, input_path=display, now=datetime.now(UTC))
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

    Exit codes: 0 found-and-parsed or not-found (informational); 1 a file was found but is
    not a usable Scorecard result (unparseable, or carrying no checks, score or date);
    2 usage error; 3 unexpected internal error.
    """

    try:
        _run_ingest_scorecard(target, input_path, output_format)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message, no traceback leak
        exit_for_unexpected(exc)
