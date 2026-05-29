"""``oss-policy-kit ingest-insights`` subcommand.

The symmetric consumer for :mod:`oss_policy_kit.cli.emit_insights` (ADR-032).
``emit-insights`` *produces* an OpenSSF Security Insights 1.0 document; this
subcommand *consumes* one that the target repository already publishes, reads it
as the project's own **self-reported** security posture, structurally validates
it, and summarizes the recognized signals.

This subcommand intentionally does **not**:

- Change ``evaluate``. No control verdict changes because a
  ``SECURITY-INSIGHTS.yml`` exists. Wiring Insights fields into specific controls
  as a ``self-attested`` evidence source is a deliberate follow-up increment
  (ADR-032 assurance fence), not part of this command.
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
import yaml

from oss_policy_kit import __version__ as _KIT_VERSION
from oss_policy_kit.application.input_limits import MAX_EVIDENCE_BYTES, read_text_capped
from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.cli.emit_insights import _INSIGHTS_SCHEMA_VERSION
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError

_PROVENANCE = "self-reported"
_TOOL_NAME = "oss-policy-kit ingest-insights"

#: Conventional locations for an OpenSSF Security Insights file, in lookup order.
#: Covers the spec-canonical ``SECURITY-INSIGHTS.yml`` (root and ``.github/``) and
#: the kit's own lowercase ``emit-insights`` default name.
_INGEST_CANDIDATES: tuple[str, ...] = (
    "SECURITY-INSIGHTS.yml",
    "SECURITY-INSIGHTS.yaml",
    ".github/SECURITY-INSIGHTS.yml",
    ".github/SECURITY-INSIGHTS.yaml",
    "security-insights.yml",
    "security-insights.yaml",
    ".github/security-insights.yml",
    ".github/security-insights.yaml",
    "docs/SECURITY-INSIGHTS.yml",
)


def _relpath(path: Path, root: Path) -> str:
    """Return *path* relative to *root* as a POSIX string, or its name if outside root."""

    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.name


def _discover_insights_file(root: Path) -> Path | None:
    """Return the first existing Security Insights file under *root*, or None."""

    for rel in _INGEST_CANDIDATES:
        p = root / rel
        if p.is_file():
            return p
    return None


def _resolve_input(target_path: Path, input_path: Path | None) -> Path | None:
    """Resolve the file to ingest: an explicit ``--input`` (must exist) or auto-discovery."""

    if input_path is None:
        return _discover_insights_file(target_path)
    chosen = input_path if input_path.is_absolute() else target_path / input_path
    if not chosen.is_file():
        raise InvalidInputError(f"--input {chosen} is not a file.")
    return chosen


def _load_insights_file(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Read + parse a Security Insights YAML file.

    Returns ``(doc, None)`` on success, or ``(None, error_message)`` when the file
    is unreadable, not valid YAML, or not a YAML mapping. Oversize files raise
    :class:`InvalidInputError` (CLI exit 2) via ``read_text_capped``.
    """

    try:
        raw = read_text_capped(path, MAX_EVIDENCE_BYTES, label="Security Insights", errors="replace")
    except OSError as exc:
        return None, f"Security Insights file is unreadable: {exc}"
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        return None, f"Security Insights file is not valid YAML: {exc}"
    if not isinstance(doc, dict):
        return None, "Security Insights file root must be a YAML mapping (object)."
    return doc, None


def _validate_ingest_structure(doc: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)`` for a parsed Security Insights document.

    Errors (exit 1) are missing required structure per the OpenSSF Security
    Insights 1.0 shape the kit knows. A declared ``schema-version`` other than the
    supported one is a *warning* (still summarizable), not an error — ingestion
    consumes third-party files and should not hard-fail a newer upstream version.
    """

    errors: list[str] = []
    warnings: list[str] = []
    if "project-lifecycle" not in doc:
        errors.append("top-level field missing: project-lifecycle")
    header = doc.get("header")
    if not isinstance(header, dict):
        errors.append("top-level field missing or not an object: header")
        return errors, warnings
    if "schema-version" not in header:
        errors.append("header.schema-version missing")
    if "last-updated" not in header:
        errors.append("header.last-updated missing")
    lifecycle = doc.get("project-lifecycle")
    if isinstance(lifecycle, dict) and "status" not in lifecycle:
        errors.append("project-lifecycle.status missing")
    sv = header.get("schema-version")
    if isinstance(sv, str) and sv != _INSIGHTS_SCHEMA_VERSION:
        warnings.append(
            f"declared schema-version {sv!r} differs from the supported {_INSIGHTS_SCHEMA_VERSION!r}; "
            "signals are summarized best-effort."
        )
    return errors, warnings


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _security_contacts(doc: dict[str, Any]) -> list[str]:
    """Collect self-reported security contacts (security-contacts[].value + email-contact)."""

    out: list[str] = []
    contacts = doc.get("security-contacts")
    if isinstance(contacts, list):
        for c in contacts:
            if isinstance(c, dict):
                v = _str_or_none(c.get("value"))
                if v and v not in out:
                    out.append(v)
    vr = doc.get("vulnerability-reporting")
    if isinstance(vr, dict):
        email = _str_or_none(vr.get("email-contact"))
        if email and email not in out:
            out.append(email)
    return out


def _distribution_points(doc: dict[str, Any]) -> list[str]:
    dp = doc.get("distribution-points")
    if not isinstance(dp, list):
        return []
    return [d for d in dp if isinstance(d, str) and d]


def _extract_signals(doc: dict[str, Any]) -> dict[str, Any]:
    """Project the recognized self-reported fields into a flat signal summary."""

    lifecycle = doc.get("project-lifecycle")
    vr = doc.get("vulnerability-reporting")
    cp = doc.get("contribution-policy")
    return {
        "project_lifecycle_status": (_str_or_none(lifecycle.get("status")) if isinstance(lifecycle, dict) else None),
        "accepts_vulnerability_reports": (
            bool(vr.get("accepts-vulnerability-reports")) if isinstance(vr, dict) else None
        ),
        "security_policy_url": (_str_or_none(vr.get("security-policy")) if isinstance(vr, dict) else None),
        "security_contacts": _security_contacts(doc),
        "accepts_pull_requests": (bool(cp.get("accepts-pull-requests")) if isinstance(cp, dict) else None),
        "has_dependency_automation_policy": "dependencies" in doc,
        "distribution_points": _distribution_points(doc),
    }


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


def _result_not_found(root: Path) -> dict[str, Any]:
    result = _base_result(found=False, input_path=None)
    result["searched_root"] = str(root)
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
        raise InvalidInputError(f"--target {target_path} is not a directory.")

    chosen = _resolve_input(target_path, input_path)
    if chosen is None:
        result = _result_not_found(target_path)
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
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message, no traceback leak
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc
