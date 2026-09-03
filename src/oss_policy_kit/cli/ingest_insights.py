"""``oss-policy-kit ingest-insights`` subcommand.

The symmetric consumer for :mod:`oss_policy_kit.cli.emit_insights` (ADR-032).
``emit-insights`` *produces* an OpenSSF Security Insights 1.0 document; this
subcommand *consumes* one that the target repository already publishes, reads it
as the project's own **self-reported** security posture, structurally validates
it, and summarizes the recognized signals.

The discover/parse/validate/extract logic lives in
:mod:`oss_policy_kit.application.insights_evidence` (the single source of truth,
shared with the ADR-033 control-evidence wiring); this module shapes the
report and renders it.

This subcommand intentionally does **not**:

- Change ``evaluate``. No control verdict changes because a
  ``SECURITY-INSIGHTS.yml`` exists *for this read-only command*. Wiring Insights
  fields into specific controls as a ``self-attested`` evidence source is the
  opt-in ``evaluate --use-insights-evidence`` path (ADR-033), not this command.
- Treat self-reported claims as proof. Output provenance is always
  ``self-reported``; the kit does not independently verify the assertions.
- Fetch external data or mutate the target. Clone-local, read-only.

See ``docs/insights-ingestion.md`` for adopter guidance and ADR-032 for the
design rationale.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit import __version__ as _KIT_VERSION
from oss_policy_kit.application.insights_evidence import (
    INSIGHTS_SCHEMA_VERSION as _INSIGHTS_SCHEMA_VERSION,
)
from oss_policy_kit.application.insights_evidence import (
    discover_insights_file as _discover_insights_file,
)
from oss_policy_kit.application.insights_evidence import (
    extract_signals as _extract_signals,
)
from oss_policy_kit.application.insights_evidence import (
    load_insights_file as _load_insights_file,
)
from oss_policy_kit.application.insights_evidence import (
    validate_ingest_structure as _validate_ingest_structure,
)
from oss_policy_kit.cli.common import app, exit_for_unexpected, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError

_PROVENANCE = "self-reported"
_TOOL_NAME = "oss-policy-kit ingest-insights"


def _relpath(path: Path, root: Path) -> str:
    """Return *path* relative to *root* as a POSIX string, or its name if outside root."""

    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def _resolve_input(target_path: Path, input_path: Path | None) -> Path | None:
    """Resolve the file to ingest: an explicit ``--input`` (must exist) or auto-discovery."""

    if input_path is None:
        return _discover_insights_file(target_path)
    chosen = input_path if input_path.is_absolute() else target_path / input_path
    if not chosen.is_file():
        # Echo the user-supplied string, never the resolved candidate: joining a
        # relative --input onto the resolved --target produces an absolute path that
        # leaks the auditor's home directory / OS username (M-002). Mirrors
        # ``export-evidence --report``.
        raise InvalidInputError(f"--input {input_path} is not a file.")
    return chosen


def _base_result(*, found: bool, input_path: str | None) -> dict[str, Any]:
    return {
        "tool": _TOOL_NAME,
        "kit_version": _KIT_VERSION,
        "schema_version_supported": _INSIGHTS_SCHEMA_VERSION,
        "found": found,
        "input_path": input_path,
        "valid": False,
        "provenance": _PROVENANCE,
        "declared_schema_version": None,
        "validation_errors": [],
        "validation_warnings": [],
        "signals": {},
    }


def _result_not_found(searched: str) -> dict[str, Any]:
    """Not-found payload; *searched* is the ``--target`` string the user typed (M-002)."""

    result = _base_result(found=False, input_path=None)
    result["searched_root"] = searched
    return result


def _result_parse_error(rel_path: str, error: str) -> dict[str, Any]:
    result = _base_result(found=True, input_path=rel_path)
    result["validation_errors"] = [error]
    return result


def _result_for_doc(doc: dict[str, Any], rel_path: str) -> dict[str, Any]:
    errors, warnings = _validate_ingest_structure(doc)
    header = doc.get("header")
    declared = header.get("schema-version") if isinstance(header, dict) else None
    result = _base_result(found=True, input_path=rel_path)
    result["valid"] = not errors
    result["declared_schema_version"] = declared if isinstance(declared, str) else None
    result["validation_errors"] = errors
    result["validation_warnings"] = warnings
    result["signals"] = _extract_signals(doc)
    return result


def _fmt_signal(value: Any) -> str:
    if value is None:
        return "(not declared)"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else "(none listed)"
    return str(value)


_SIGNAL_LABELS: tuple[tuple[str, str], ...] = (
    ("project_lifecycle_status", "project lifecycle status"),
    ("accepts_vulnerability_reports", "accepts vulnerability reports"),
    ("security_policy_url", "security policy"),
    ("security_contacts", "security contacts"),
    ("accepts_pull_requests", "accepts pull requests"),
    ("has_dependency_automation_policy", "dependency automation policy declared"),
    ("distribution_points", "distribution points"),
)


def _render_human(result: dict[str, Any]) -> None:
    if not result["found"]:
        lines = [
            "Security Insights - none found",
            f"  Searched under: {result['searched_root']}",
            "  No SECURITY-INSIGHTS.yml (or security-insights.yml) found; nothing to ingest.",
        ]
        write_stdout_text("\n".join(lines) + "\n")
        return
    state = "valid" if result["valid"] else "INVALID (structural)"
    lines = [
        f"Security Insights - ingested ({_PROVENANCE}); structurally {state}",
        f"  File: {result['input_path']}",
        f"  Declared schema-version: {result['declared_schema_version'] or '(unset)'} "
        f"(supported: {result['schema_version_supported']})",
    ]
    lines += [f"  ERROR: {e}" for e in result["validation_errors"]]
    lines += [f"  warning: {w}" for w in result["validation_warnings"]]
    lines.append("")
    lines.append("  Self-reported signals (NOT independently verified by the kit):")
    signals = result["signals"]
    lines += [f"    - {label}: {_fmt_signal(signals.get(key))}" for key, label in _SIGNAL_LABELS]
    lines.append("")
    lines.append(
        "  Note: these values are self-asserted by the project. ingest-insights reports them; "
        "it does not verify them and does not change any `evaluate` gate."
    )
    write_stdout_text("\n".join(lines) + "\n")


def _run_ingest_insights(target: Path, input_path: Path | None, output_format: str) -> None:
    fmt = output_format.lower().strip()
    if fmt not in {"human", "json"}:
        raise InvalidInputError("--format must be human or json.")
    target_path = target.resolve()
    if not target_path.is_dir():
        # Echo the user-supplied string, never target.resolve(): the absolute
        # path leaks the auditor's home directory / username (M-002).
        raise InvalidInputError(f"--target {target} is not a directory.")

    chosen = _resolve_input(target_path, input_path)
    if chosen is None:
        # The JSON report is shareable; cite the typed --target, not its resolved form.
        result = _result_not_found(str(target))
    else:
        doc, error = _load_insights_file(chosen)
        rel = _relpath(chosen, target_path)
        if error is not None or doc is None:
            result = _result_parse_error(rel, error or "Security Insights file could not be parsed.")
        else:
            result = _result_for_doc(doc, rel)

    if fmt == "json":
        write_stdout_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    else:
        _render_human(result)

    if result["found"] and not result["valid"]:
        raise typer.Exit(code=1)


@app.command("ingest-insights", rich_help_panel=CMD_PANEL_EXPORT)
def ingest_insights_cmd(
    target: Path = typer.Option(
        Path("."),
        "--target",
        help="Path to the repository to inspect for a Security Insights file. Defaults to current directory.",
    ),
    input_path: Path | None = typer.Option(
        None,
        "--input",
        help="Explicit path to a Security Insights YAML. Overrides auto-discovery under --target.",
    ),
    output_format: str = typer.Option(
        "human",
        "--format",
        help="Output format: human (default) or json.",
    ),
) -> None:
    """Ingest and summarize a target's OpenSSF Security Insights file (self-reported).

    Discovers ``SECURITY-INSIGHTS.yml`` (or the kit's ``security-insights.yml``) under
    ``--target``, structurally validates it, and reports the self-reported signals.
    The symmetric consumer for ``emit-insights``; see ADR-032 and
    docs/insights-ingestion.md.

    Exit codes: 0 found-and-valid or not-found (informational); 1 found-but-invalid;
    2 usage error; 3 unexpected internal error.
    """

    try:
        _run_ingest_insights(target, input_path, output_format)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    # Last-resort user message, no traceback leak.
    except Exception as exc:  # noqa: BLE001
        exit_for_unexpected(exc)
