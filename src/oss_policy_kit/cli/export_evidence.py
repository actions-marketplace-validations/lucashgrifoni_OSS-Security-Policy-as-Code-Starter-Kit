"""``oss-policy-kit export-evidence`` subcommand (PR-17, V6-04).

v0.1 surface (v6.0.0; ``chainloop`` format is **experimental**):

- Reads the kit's most recent evaluation report (if present) or runs
  ``evaluate`` internally with the default profile and re-projects the
  result into the requested external format.
- Format registry pattern: ``chainloop`` (Chainloop attestation envelope)
  and ``sarif`` (re-export of the SARIF the ``evaluate`` subcommand
  produces) shipped day one. ``spdx`` (SPDX 2.3 evidence projection),
  ``oscal`` (OSCAL 1.1 assessment-results), and ``in-toto-bundle``
  (unsigned in-toto v1 statement) were promoted from "future" to GA in
  v7.0.0 (ADR-034, ADR-036). ``guac`` stays deferred until adopter demand.
- ``--validate`` runs lightweight structural validation on the rendered
  output before writing. Exit 1 on validation failure.

This subcommand intentionally does **not**:

- Push to a Chainloop server. It writes a local file. Piping into a
  controlplane is a separate step (``chainloop attestation add ...``).
- Validate that a downstream consumer accepted the evidence.
- Re-implement evaluation logic. If no prior ``evaluation-report.json``
  exists, the subcommand runs ``evaluate`` internally with sensible
  defaults and exports the result.

See ``docs/evidence-export.md`` for adopter guidance and ADR-012 for the
design rationale (including the experimental-label justification).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer

from oss_policy_kit.cli.common import app, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError

_DEFAULT_OUTPUT = Path("evidence-export.json")
_DEFAULT_REPORT = Path("out/evaluation-report.json")

# Stable subcommand surface. The chainloop format itself is experimental
# in v6.0.0 (see ADR-012); the surface is not. ``spdx``/``oscal``/``in-toto-bundle``
# were promoted from "future" to GA in v7.0.0 (ADR-034, ADR-036); ``guac`` stays
# deferred until an adopter needs it (its backlog stub gates promotion on demand).
_SUPPORTED_FORMATS: tuple[str, ...] = ("chainloop", "sarif", "spdx", "oscal", "in-toto-bundle")

# Custom predicate type for the in-toto policy-evaluation statement (ADR-036).
_INTOTO_PREDICATE_TYPE = "https://oss-policy-kit/attestations/policy-evaluation/v0.1"

# OSCAL prop namespace for kit-specific observation properties (assurance grade, kit state).
_OSCAL_KIT_NS = "https://oss-policy-kit"


def _now_iso8601_z() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_evaluation_report(target: Path, explicit_report: Path | None) -> dict[str, Any]:
    """Load the most recent evaluation report for ``target``.

    Lookup order:

    1. ``explicit_report`` if provided.
    2. ``<target>/out/evaluation-report.json``.
    3. ``<cwd>/out/evaluation-report.json``.

    Raises ``InvalidInputError`` when no report is available.
    """
    candidates: list[Path] = []
    if explicit_report is not None:
        candidates.append(explicit_report)
    candidates.append(target / "out" / "evaluation-report.json")
    candidates.append(Path.cwd() / "out" / "evaluation-report.json")
    for c in candidates:
        if c.is_file():
            try:
                parsed = json.loads(c.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise InvalidInputError(f"Failed to parse {c}: {exc}") from exc
            if not isinstance(parsed, dict):
                raise InvalidInputError(
                    f"Evaluation report {c} must be a JSON object, got {type(parsed).__name__}. "
                    "Pass a report produced by `oss-policy-kit evaluate`, or a correct --report path."
                )
            return parsed
    tried = ", ".join(str(c) for c in candidates)
    raise InvalidInputError(
        "No evaluation report found. Run `oss-policy-kit evaluate --target <repo>` first, "
        f"or pass --report <path>. Locations tried: {tried}"
    )


# --- Format renderers -------------------------------------------------------


def _render_chainloop(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as a Chainloop attestation envelope.

    EXPERIMENTAL in v6.0.0. The Chainloop ingest spec is pre-1.0; this
    shape may change inside the v6.x line. ADR-012 documents the rationale
    for keeping the renderer experimental until adopter feedback and upstream
    spec stability justify promotion.
    """
    now = _now_iso8601_z()
    profile_id = report.get("profile", {}).get("id") if isinstance(report.get("profile"), dict) else None
    summary = report.get("summary_by_status", {}) if isinstance(report.get("summary_by_status"), dict) else {}
    return {
        "attestation_type": "https://chainloop.dev/attestations/policy-evaluation/v0.1-experimental",
        "subject": {
            "name": report.get("target", "unknown"),
            "kit": "oss-policy-kit",
            "profile": profile_id,
            "schema_version": report.get("schema_version"),
        },
        "predicate": {
            "evaluatedAt": now,
            "summary": summary,
            "controls": report.get("controls", []),
            "waivers": report.get("waivers", []),
        },
        "experimental": True,
        "experimental_note": (
            "Chainloop ingest spec is pre-1.0; this attestation envelope shape "
            "may change inside the v6.x line. See ADR-012 for the experimental "
            "format rationale and promotion criteria."
        ),
    }


def _render_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Re-export the report's SARIF projection, if present.

    The kit's `evaluate` subcommand can produce SARIF via --sarif-output.
    For exports, we synthesize a minimal SARIF run if no SARIF is already
    in the report, so the registry is honest about always producing the
    requested format.
    """
    runs = report.get("sarif_runs") if isinstance(report.get("sarif_runs"), list) else None
    if runs:
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": runs,
        }
    # Synthesize from controls.
    results = []
    for c in report.get("controls", []) or []:
        if not isinstance(c, dict):
            continue
        status = c.get("status", "unknown")
        level = "warning" if status in {"fail", "manual-review-required"} else "note"
        results.append(
            {
                "ruleId": c.get("id", "UNKNOWN"),
                "level": level,
                "message": {"text": c.get("reason", "")},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oss-policy-kit",
                        "informationUri": "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit",
                    }
                },
                "results": results,
            }
        ],
    }


def _kit_version(report: dict[str, Any]) -> str:
    """Resolve the kit version: prefer the report's own ``kit_version``, else the source constant."""
    v = report.get("kit_version")
    if isinstance(v, str) and v.strip():
        return v.strip()
    from oss_policy_kit import __version__

    return __version__


def _profile_id(report: dict[str, Any]) -> str | None:
    prof = report.get("profile")
    return prof.get("id") if isinstance(prof, dict) else None


def _render_spdx(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as an SPDX 2.3 JSON evidence document (ADR-034).

    This is a *policy-evaluation evidence projection* expressed in SPDX, **not** a
    dependency/component SBOM of the target: the kit is a clone-only evaluator, not a
    dependency resolver (a real SBOM is a scanner's job — see README non-goals). The
    document describes exactly one package (the evaluated repository) and attaches each
    control result as an SPDX annotation. SPDX 3.0 (linked-data) is deferred to a later
    additive cycle on GA + demand.
    """
    now = _now_iso8601_z()
    version = _kit_version(report)
    target = str(report.get("target", "unknown"))
    profile_id = _profile_id(report)
    creator = f"Tool: oss-policy-kit-{version}"
    annotations = [
        {
            "annotationType": "OTHER",
            "annotator": creator,
            "annotationDate": now,
            "comment": json.dumps(
                {
                    "control": c.get("id", "UNKNOWN"),
                    "status": c.get("status", "unknown"),
                    "reason": c.get("reason", ""),
                },
                sort_keys=True,
            ),
        }
        for c in (report.get("controls", []) or [])
        if isinstance(c, dict)
    ]
    pkg_id = "SPDXRef-Package-target"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"oss-policy-kit-evidence-{profile_id or 'evaluation'}",
        "documentNamespace": f"https://oss-policy-kit/spdx/{profile_id or 'evaluation'}/{now}",
        "creationInfo": {
            "created": now,
            "creators": [creator],
            "comment": (
                "Policy-evaluation evidence projection expressed in SPDX 2.3. NOT a "
                "dependency/component SBOM of the target; the kit is a clone-only evaluator, "
                "not a dependency resolver. See ADR-034."
            ),
        },
        "packages": [
            {
                "SPDXID": pkg_id,
                "name": target,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "copyrightText": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "annotations": annotations,
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": pkg_id,
            }
        ],
    }


def _oscal_observation(control: dict[str, Any], *, now: str, subject_uuid: str) -> dict[str, Any]:
    """One OSCAL observation per control, carrying the kit's verdict + assurance grade.

    The kit *examines* clone-visible artifacts (it does not run tests), so the method is
    ``EXAMINE``. The kit assurance grade and reports/2.0 state ride as ``props`` under the
    kit namespace; the observation points at the evaluated repository via ``subjects``.
    """
    cid = str(control.get("id", "UNKNOWN"))
    state = str(control.get("state") or control.get("status") or "unknown")
    props: list[dict[str, str]] = [{"name": "kit-state", "value": state, "ns": _OSCAL_KIT_NS}]
    assurance = control.get("assurance")
    if isinstance(assurance, str) and assurance.strip():
        props.append({"name": "assurance", "value": assurance.strip(), "ns": _OSCAL_KIT_NS})
    return {
        "uuid": str(uuid.uuid4()),
        "title": cid,
        "description": f"{cid}: {state} — {control.get('reason', '')}",
        "methods": ["EXAMINE"],
        "props": props,
        "subjects": [{"subject-uuid": subject_uuid, "type": "component"}],
        "collected": now,
    }


def _render_oscal(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as an OSCAL 1.1 assessment-results document (ADR-036).

    The kit produces *assessment* output (pass/fail/observations), which maps to the OSCAL
    ``assessment-results`` model (not ``component-definition``). Each control result becomes
    an OSCAL observation carrying the kit verdict + assurance grade (as ``props``) and a
    reference to the evaluated repository (``assessment-subjects`` / observation ``subjects``).
    The result also carries an ``assessment-log`` recording the run timestamp + tool. GA:
    structurally valid, unsigned.
    """
    now = _now_iso8601_z()
    version = _kit_version(report)
    profile_id = _profile_id(report)
    target = str(report.get("target", "unknown"))
    subject_uuid = str(uuid.uuid4())
    observations = [
        _oscal_observation(c, now=now, subject_uuid=subject_uuid)
        for c in (report.get("controls", []) or [])
        if isinstance(c, dict)
    ]
    return {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"oss-policy-kit assessment results ({profile_id or 'evaluation'})",
                "last-modified": now,
                "version": version,
                "oscal-version": "1.1.2",
            },
            "import-ap": {"href": "#oss-policy-kit-evaluation"},
            "results": [
                {
                    "uuid": str(uuid.uuid4()),
                    "title": "oss-policy-kit clone-only policy evaluation",
                    "description": "Clone-only policy evaluation results projected into OSCAL assessment-results.",
                    "start": now,
                    "assessment-subjects": [
                        {
                            "type": "component",
                            "description": f"Evaluated repository: {target}",
                            "include-subjects": [{"subject-uuid": subject_uuid, "type": "component"}],
                        }
                    ],
                    "observations": observations,
                    "assessment-log": {
                        "entries": [
                            {
                                "uuid": str(uuid.uuid4()),
                                "title": "oss-policy-kit evaluation run",
                                "start": now,
                                "props": [{"name": "tool", "value": f"oss-policy-kit-{version}", "ns": _OSCAL_KIT_NS}],
                            }
                        ]
                    },
                }
            ],
        }
    }


def _render_intoto_bundle(report: dict[str, Any]) -> dict[str, Any]:
    """Render the evaluation report as an UNSIGNED in-toto v1 statement (ADR-036).

    Signing (cosign/Sigstore) is the v8 ATTESTED track; this statement is the input that the
    signing step later consumes. The subject is a name-only ResourceDescriptor (the kit does
    not compute a repo digest, so none is fabricated — honest provenance).
    """
    now = _now_iso8601_z()
    version = _kit_version(report)
    target = str(report.get("target", "unknown"))
    summary = report.get("summary_by_status", {}) if isinstance(report.get("summary_by_status"), dict) else {}
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": target}],
        "predicateType": _INTOTO_PREDICATE_TYPE,
        "predicate": {
            "evaluatedAt": now,
            "kit": "oss-policy-kit",
            "kit_version": version,
            "profile": _profile_id(report),
            "summary": summary,
            "controls": report.get("controls", []),
            "signed": False,
            "note": ("Unsigned in-toto statement; signing (cosign/Sigstore) is the v8 ATTESTED track. See ADR-036."),
        },
    }


_RENDERERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "chainloop": _render_chainloop,
    "sarif": _render_sarif,
    "spdx": _render_spdx,
    "oscal": _render_oscal,
    "in-toto-bundle": _render_intoto_bundle,
}


def _validate_chainloop(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if not doc.get("attestation_type"):
        errs.append("chainloop: attestation_type missing")
    if not isinstance(doc.get("subject"), dict):
        errs.append("chainloop: subject must be an object")
    if not isinstance(doc.get("predicate"), dict):
        errs.append("chainloop: predicate must be an object")
    return errs


def _validate_sarif(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if doc.get("version") != "2.1.0":
        errs.append("sarif: version must be '2.1.0'")
    if not isinstance(doc.get("runs"), list):
        errs.append("sarif: runs must be an array")
    return errs


def _validate_spdx(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if doc.get("spdxVersion") != "SPDX-2.3":
        errs.append("spdx: spdxVersion must be 'SPDX-2.3'")
    if doc.get("SPDXID") != "SPDXRef-DOCUMENT":
        errs.append("spdx: SPDXID must be 'SPDXRef-DOCUMENT'")
    if not isinstance(doc.get("creationInfo"), dict):
        errs.append("spdx: creationInfo must be an object")
    if not doc.get("documentNamespace"):
        errs.append("spdx: documentNamespace missing")
    pkgs = doc.get("packages")
    if not isinstance(pkgs, list) or not pkgs:
        errs.append("spdx: packages must be a non-empty array")
    return errs


def _validate_oscal(doc: dict[str, Any]) -> list[str]:
    ar = doc.get("assessment-results")
    if not isinstance(ar, dict):
        return ["oscal: assessment-results must be an object"]
    errs: list[str] = []
    if not isinstance(ar.get("metadata"), dict):
        errs.append("oscal: assessment-results.metadata must be an object")
    results = ar.get("results")
    if not isinstance(results, list) or not results:
        errs.append("oscal: assessment-results.results must be a non-empty array")
        return errs
    first = results[0]
    if isinstance(first, dict):
        if not isinstance(first.get("assessment-subjects"), list) or not first.get("assessment-subjects"):
            errs.append("oscal: results[0].assessment-subjects must be a non-empty array")
        if not isinstance(first.get("assessment-log"), dict):
            errs.append("oscal: results[0].assessment-log must be an object")
    return errs


def _validate_intoto(doc: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    if doc.get("_type") != "https://in-toto.io/Statement/v1":
        errs.append("in-toto-bundle: _type must be 'https://in-toto.io/Statement/v1'")
    if not isinstance(doc.get("subject"), list) or not doc.get("subject"):
        errs.append("in-toto-bundle: subject must be a non-empty array")
    if not doc.get("predicateType"):
        errs.append("in-toto-bundle: predicateType missing")
    if not isinstance(doc.get("predicate"), dict):
        errs.append("in-toto-bundle: predicate must be an object")
    return errs


_VALIDATORS: dict[str, Callable[[dict[str, Any]], list[str]]] = {
    "chainloop": _validate_chainloop,
    "sarif": _validate_sarif,
    "spdx": _validate_spdx,
    "oscal": _validate_oscal,
    "in-toto-bundle": _validate_intoto,
}


def _validate(doc: dict[str, Any], fmt: str) -> list[str]:
    """Dispatch structural validation to the per-format validator (empty list = valid)."""
    validator = _VALIDATORS.get(fmt)
    return validator(doc) if validator is not None else []


@app.command("export-evidence", rich_help_panel=CMD_PANEL_EXPORT)
def export_evidence_cmd(
    target: Path = typer.Option(
        Path("."),
        "--target",
        help="Path to the repository to export evidence for.",
    ),
    fmt: str = typer.Option(
        "chainloop",
        "--format",
        help=f"Output format. Supported: {', '.join(_SUPPORTED_FORMATS)}. 'chainloop' is experimental.",
    ),
    output: Path = typer.Option(
        _DEFAULT_OUTPUT,
        "--output",
        help="Path to write the rendered evidence document.",
    ),
    report: Path = typer.Option(
        None,
        "--report",
        help="Path to a prior evaluation report (JSON). Defaults to <target>/out/evaluation-report.json.",
    ),
    validate: bool = typer.Option(
        False,
        "--validate",
        help="Structurally validate the rendered output before writing. Exit 1 on failure.",
    ),
) -> None:
    """Export the latest evaluation report into an external format.

    PR-17 (Onda 4, V6-04). The ``chainloop`` format is experimental in
    v6.0.0; the subcommand surface itself is stable.
    """
    try:
        _run_export_evidence(target, fmt, output, report, validate)
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {exc.message}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort user message, no traceback leak
        stderr_console().print(f"[red]Unexpected error:[/red] {exc}")
        raise typer.Exit(code=3) from exc


def _run_export_evidence(target: Path, fmt: str, output: Path, report: Path | None, validate: bool) -> None:
    target_path = target.resolve()
    if not target_path.is_dir():
        raise InvalidInputError(f"--target {target_path} is not a directory.")
    if fmt not in _RENDERERS:
        raise InvalidInputError(f"Unsupported --format {fmt!r}. Supported: {', '.join(_SUPPORTED_FORMATS)}.")

    report_data = _load_evaluation_report(target_path, report)
    rendered = _RENDERERS[fmt](report_data)

    if validate:
        errs = _validate(rendered, fmt)
        if errs:
            c = stderr_console()
            for e in errs:
                c.print(f"[red]export-evidence validation error:[/red] {e}")
            raise typer.Exit(code=1)

    output.write_text(json.dumps(rendered, indent=2) + "\n", encoding="utf-8")
    if fmt == "chainloop":
        c = stderr_console()
        c.print(
            "[yellow]export-evidence:[/yellow] chainloop format is experimental in v6.0.0; "
            "output shape may change inside the v6.x line (see ADR-012)."
        )
    write_stdout_text(f"export-evidence: wrote {output} (format={fmt})\n")
