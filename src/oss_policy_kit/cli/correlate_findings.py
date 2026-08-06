"""``oss-policy-kit correlate-findings`` subcommand (ADR-030 A-S6).

The first user-visible surface of the normalized finding model. It reads the
scanner evidence already on disk (the six kit evidence JSONs + the four external
SARIF drops), normalizes and correlates them into one deduplicated, ranked set,
and writes the ``oss-policy-kit/findings/1.0`` artifact.

Stateless and read-only (anti-ASPM fence): a single clone-only run, no network,
no persistence beyond the one output file, no cross-run state. It composes
scanner verdicts — it never re-scans, never re-scores, and never changes any
``evaluate`` control state or gate. The optional ``--fail-on-*`` flags gate on
the correlated finding set only.

Exit codes: 0 ok (incl. no sources / no findings); 1 a ``--fail-on-*`` gate
tripped; 2 usage/validation (bad ``--format``/``--fail-on-severity``, bad
``--target``, oversized ``--waivers``, unwritable ``--output``); 3 unexpected
internal error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit import __version__ as _KIT_VERSION
from oss_policy_kit.application.finding_normalization import NORMALIZED_SEVERITIES
from oss_policy_kit.application.findings_report import build_findings_report
from oss_policy_kit.application.findings_sarif_export import render_findings_sarif
from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES, oversize_reason
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError

_DEFAULT_OUTPUT = Path(".oss-policy-kit") / "findings.json"
_HUMAN_TABLE_CAP = 25

# Severity rank (higher = more urgent); index into the ordered vocabulary.
_SEVERITY_RANK = {name: len(NORMALIZED_SEVERITIES) - i for i, name in enumerate(NORMALIZED_SEVERITIES)}
_GATE_SEVERITIES = ("critical", "high", "medium", "low")


def _render_human(report: dict[str, Any], output: Path) -> None:
    findings = report["findings"]
    by_sev = report["findings_by_severity"]
    sources = report["sources_read"]
    ok = sum(1 for s in sources if s["status"] == "ok")
    corr = report["correlation"]

    lines = [
        f"Normalized findings - {report['findings_total']} total "
        f"(from {len(sources)} sources: {ok} ok, {len(sources) - ok} not read; "
        f"{corr['merged_groups']} merged, {corr['cross_tool_merges']} cross-tool)",
        "  by severity: " + "  ".join(f"{name}={by_sev[name]}" for name in NORMALIZED_SEVERITIES if by_sev[name]),
    ]
    if report["findings_total"] == 0:
        lines.append("  (no findings correlated from the available scanner evidence)")
    for f in findings[:_HUMAN_TABLE_CAP]:
        loc = f["location"]
        where = loc["file"] or (loc["logical"]["resource_name"] or loc["logical"]["name"] or "-")
        if loc["file"] and loc["line_start"]:
            where = f"{loc['file']}:{loc['line_start']}"
        tags = []
        if f["waiver"]["waived"]:
            tags.append("WAIVED")
        if f["kev"]:
            tags.append("KEV")
        if f["epss"] is not None:
            tags.append(f"EPSS={f['epss']:.2f}")
        if f["correlation"]["merged_from"] > 1:
            tags.append(f"merged x{f['correlation']['merged_from']}")
        suffix = f"   ({', '.join(tags)})" if tags else ""
        lines.append(
            f"  #{f['priority']['rank']:<3} [{f['severity']['normalized'].upper():<8}] {f['rule']}  {where}{suffix}"
        )
    remaining = report["findings_total"] - _HUMAN_TABLE_CAP
    if remaining > 0:
        lines.append(f"  ... and {remaining} more (see {output})")
    lines.append("")
    lines.append(f"Wrote findings/1.0 artifact: {output}")
    write_stdout_text("\n".join(lines) + "\n")


def _write_artifact(report: dict[str, Any], output: Path) -> None:
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    try:
        if output.parent != Path(""):
            output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
    except OSError as exc:
        # strerror only: never leak the absolute path / username (v9.0.2 M-002).
        raise InvalidInputError(f"cannot write --output ({exc.strerror or 'filesystem error'})") from exc


def _gate_tripped(report: dict[str, Any], fail_on_severity: str | None, fail_on_kev: bool) -> str | None:
    """Return a gate message if a --fail-on-* threshold is met, else None."""

    # Waived findings stay visible in the artifact but do not trip the gates
    # (the waiver effect is confined to this surface - FT-3).
    active = [f for f in report["findings"] if not f["waiver"]["waived"]]
    if fail_on_kev and any(f["kev"] for f in active):
        n = sum(1 for f in active if f["kev"])
        return f"{n} KEV-listed finding(s) present (--fail-on-kev)."
    if fail_on_severity:
        threshold = _SEVERITY_RANK[fail_on_severity]
        hits = [f for f in active if _SEVERITY_RANK.get(f["severity"]["normalized"], 0) >= threshold]
        if hits:
            return f"{len(hits)} finding(s) at or above severity '{fail_on_severity}' (--fail-on-severity)."
    return None


def _resolve_paths(
    target: str, output: Path, waivers: Path | None, enrichment_file: Path | None
) -> tuple[Path, Path, Path | None, Path | None]:
    """Validate --target and anchor RELATIVE --output/--waivers/--enrichment-file under it.

    Evidence is read from --target, so a relative output/waivers/enrichment path
    resolves under --target too (the whole chain reads and writes in one place;
    mirrors scan-*). An absolute path is always honored verbatim. Returns
    ``(target_path, output_path, waivers_path, enrichment_path)``.
    """

    # Reject an empty/whitespace --target instead of silently coercing "" to cwd.
    # (Kept as a str up to here so the raw empty string is not lost to Path("")==".").
    if not target.strip():
        raise InvalidInputError("--target must not be empty.")
    target_path = Path(target).resolve()
    if not target_path.is_dir():
        # Echo the user-supplied string, never target.resolve(): the absolute
        # path leaks the auditor's home directory / username (M-002).
        raise InvalidInputError(f"--target {target} is not a directory.")

    output_path = output if output.is_absolute() else target_path / output

    waivers_path: Path | None = None
    if waivers is not None:
        waivers_path = waivers if waivers.is_absolute() else target_path / waivers
        if not waivers_path.is_file():
            raise InvalidInputError(f"--waivers {waivers} is not a file.")
        # Same 5 MiB cap `evaluate --waivers` enforces on the same file. Without it the
        # YAML loader spends seconds on the whole document and the operator's waivers
        # are then dropped with no message - one flag behaving two ways.
        oversize = oversize_reason(waivers_path, MAX_EVIDENCE_BYTES, label="Waivers")
        if oversize is not None:
            raise InvalidInputError(oversize)
    enrichment_path: Path | None = None
    if enrichment_file is not None:
        enrichment_path = enrichment_file if enrichment_file.is_absolute() else target_path / enrichment_file
        if not enrichment_path.is_file():
            raise InvalidInputError(f"--enrichment-file {enrichment_file.name} is not a file.")
    return target_path, output_path, waivers_path, enrichment_path


def _run_correlate_findings(
    target: str,
    output: Path,
    output_format: str,
    fail_on_severity: str | None,
    fail_on_kev: bool,
    include_absolute_path: bool,
    waivers: Path | None,
    enrichment_file: Path | None,
) -> None:
    fmt = output_format.lower().strip()
    if fmt not in {"human", "json", "sarif"}:
        raise InvalidInputError("--format must be human, json, or sarif.")
    # Distinguish "flag omitted" (None) from "flag supplied empty" (""). The old idiom
    # `x.strip().lower() if x else None` collapsed both to None, so --fail-on-severity ""
    # silently disarmed the gate and exited 0, while "  " correctly exited 2. An empty
    # value is what a shell produces from --fail-on-severity "$SEVERITY" with SEVERITY
    # unset — precisely when the gate must stay armed.
    sev: str | None = None
    if fail_on_severity is not None:
        sev = fail_on_severity.lower().strip()
        if sev not in _GATE_SEVERITIES:
            raise InvalidInputError("--fail-on-severity must be one of: critical, high, medium, low.")

    target_path, output_path, waivers_path, enrichment_path = _resolve_paths(target, output, waivers, enrichment_file)
    report = build_findings_report(
        target_path,
        kit_version=_KIT_VERSION,
        include_absolute_path=include_absolute_path,
        waivers_path=waivers_path,
        enrichment_path=enrichment_path,
    )
    for w in report.get("extensions", {}).get("waiver_warnings", []):
        stderr_console().print(f"[yellow]Waivers:[/yellow] {markup_safe(w)}")
    _write_artifact(report, output_path)

    if fmt == "json":
        write_stdout_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    elif fmt == "sarif":
        write_stdout_text(json.dumps(render_findings_sarif(report), indent=2, sort_keys=True) + "\n")
    else:
        _render_human(report, output_path)

    message = _gate_tripped(report, sev, fail_on_kev)
    if message is not None:
        stderr_console().print(f"[yellow]Gate:[/yellow] {markup_safe(message)}")
        raise typer.Exit(code=1)


@app.command("correlate-findings", rich_help_panel=CMD_PANEL_EXPORT)
def correlate_findings_cmd(
    target: str = typer.Option(
        ".",
        "--target",
        help="Repository clone to correlate scanner evidence for. Defaults to current directory.",
    ),
    output: Path = typer.Option(
        _DEFAULT_OUTPUT,
        "--output",
        "-o",
        help=(
            "Path to write the findings/1.0 JSON artifact. A relative path resolves under "
            "--target (so evidence and artifact stay together); an absolute path is honored "
            "as-is. Default: <target>/.oss-policy-kit/findings.json."
        ),
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help="stdout view: human (ranked summary, default), json (the full artifact), or sarif (aggregator SARIF).",
    ),
    fail_on_severity: str | None = typer.Option(
        None,
        "--fail-on-severity",
        help="Exit 1 if any correlated finding is at or above this severity (critical|high|medium|low).",
    ),
    fail_on_kev: bool = typer.Option(
        False,
        "--fail-on-kev",
        help="Exit 1 if any correlated finding is CISA KEV-listed.",
    ),
    include_absolute_path: bool = typer.Option(
        False,
        "--include-absolute-path",
        help="Emit the absolute target path in the artifact instead of the privacy-default basename.",
    ),
    waivers: Path | None = typer.Option(
        None,
        "--waivers",
        help=(
            "Optional waivers.yaml (a relative path resolves under --target); entries with "
            "vulnerability_ids mark matching findings as waived (visible, but exempt from "
            "--fail-on-* gates). Never affects evaluate."
        ),
    ),
    enrichment_file: Path | None = typer.Option(
        None,
        "--enrichment-file",
        help=(
            "Optional offline EPSS/KEV snapshot (JSON with as_of + vulnerabilities map; a "
            "relative path resolves under --target). Inferred-trust input: refines ranking "
            "order/rationale only; never changes finding fields, severities, gates, or "
            "control state."
        ),
    ),
) -> None:
    """Correlate scanner evidence into one deduplicated, ranked findings/1.0 artifact.

    Reads the six kit evidence JSONs plus the four external SARIF drops under
    ``--target``, normalizes them into one vocabulary, deduplicates/correlates
    across scanners by a deterministic key, ranks by KEV then EPSS then severity,
    and writes ``findings/1.0`` to ``--output``. Read-only and stateless — it
    composes scanner verdicts and changes no ``evaluate`` control state or gate.
    Missing or unreadable evidence is recorded honestly in ``sources_read``, never
    raised. The optional ``--fail-on-*`` flags gate on the correlated set only.

    Exit codes: 0 ok; 1 a --fail-on-* gate tripped; 2 usage/validation; 3 internal.
    """

    try:
        _run_correlate_findings(
            target,
            output,
            output_format,
            fail_on_severity,
            fail_on_kev,
            include_absolute_path,
            waivers,
            enrichment_file,
        )
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message, no traceback leak
        exit_for_unexpected(exc)
