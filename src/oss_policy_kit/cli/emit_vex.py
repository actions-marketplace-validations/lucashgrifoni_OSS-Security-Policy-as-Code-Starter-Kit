"""``oss-policy-kit emit-vex`` subcommand.

v0.2 surface (v5.9.0):

- Reads OSV-Scanner SARIF output (the same evidence ``SAST-OSV-068`` consumes).
- Optionally reads ``waivers/waivers.yaml`` and applies any waiver carrying a
  ``vulnerability_ids: [...]`` field to mark matching findings as
  ``not_affected`` with the waiver justification text.
- Findings without a matching waiver default to ``state: in_triage`` — the
  neutral CycloneDX state meaning "manufacturer is analyzing".
- ``--validate`` performs structural validation against the CycloneDX VEX 1.6
  required-field set (no external schema bundle needed).
- ``--include-references`` embeds OSV / GHSA advisory URLs when the SARIF
  exposes them via rule ``helpUri`` / ``help.text``.

v6.6.0 adds ``--format {cyclonedx,openvex}`` (default ``cyclonedx``): the same
waiver/exploitability data can be emitted as OpenVEX v0.2.0 alongside CycloneDX
VEX 1.6. ``--product`` supplies the OpenVEX product identity (see ADR-031).

This subcommand intentionally does **not**:

- Generate an SBOM (use Syft / Trivy / language-native tooling).
- Verify the manufacturer's analysis (the auditor does that).
- Mutate the OSV SARIF (read-only).
"""

from __future__ import annotations

import json
from itertools import islice
from pathlib import Path
from typing import Any

import typer

# Hoisted to the shared application layer in v10.0.0 (A-S7) so correlate-findings
# reads the same vulnerability_ids-keyed entries. Aliased to the historical private
# names so behavior and existing test hooks stay byte-identical.
from oss_policy_kit.application import vuln_waivers as _vuln_waivers_mod
from oss_policy_kit.application.input_limits import (
    MAX_SARIF_BYTES,
    bad_input_detail,
    oversize_reason,
    too_deep_reason,
)
from oss_policy_kit.application.vuln_waivers import (
    CDX_JUSTIFICATIONS as _CDX_JUSTIFICATIONS,
)
from oss_policy_kit.application.vuln_waivers import (
    VulnWaiver as _VulnWaiver,
)
from oss_policy_kit.application.vuln_waivers import (
    load_vuln_waivers as _load_vuln_waivers,
)
from oss_policy_kit.cli.common import app, markup_safe, stderr_console, write_stdout_text
from oss_policy_kit.cli.help_text import CMD_PANEL_EXPORT
from oss_policy_kit.domain.errors import InvalidInputError, OssPolicyKitError
from oss_policy_kit.domain.models import utc_now

# Test-visible back-compat hooks for the historical private helper names (A-S7 hoist).
# Plain assignments (not imports) so lint autofix never strips them.
_parse_waiver_expiry = _vuln_waivers_mod.parse_waiver_expiry
_parse_cdx_justification = _vuln_waivers_mod.parse_cdx_justification
_parse_vuln_waiver_entry = _vuln_waivers_mod.parse_vuln_waiver_entry

# Canonical evidence path the SAST-OSV-068 adapter consumes.
_DEFAULT_OSV_SARIF = Path(".oss-policy-kit/evidence/sast/osv-scanner.sarif.json")
_DEFAULT_WAIVERS = Path("waivers/waivers.yaml")

_VEX_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# --- OpenVEX (v0.2.0) constants and CycloneDX→OpenVEX mappings --------------
# See ADR-031 and docs/vex-emission.md for the equivalence rationale.

_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_OPENVEX_AUTHOR = "oss-policy-kit emit-vex"
# Placeholder product @id emitted when --product is omitted (a loud stderr
# warning accompanies it; the document is structurally valid but the operator
# must set a real product identifier before distribution).
_OPENVEX_PRODUCT_PLACEHOLDER = "pkg:generic/UNKNOWN"

_OPENVEX_STATUSES: frozenset[str] = frozenset({"not_affected", "affected", "fixed", "under_investigation"})

_OPENVEX_JUSTIFICATIONS: frozenset[str] = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)

# CycloneDX analysis.state → OpenVEX status. The kit emits only in_triage and
# not_affected today; the remaining rows are mapped for forward-compatibility
# but are not produced speculatively.
_CDX_STATE_TO_OPENVEX_STATUS: dict[str, str] = {
    "in_triage": "under_investigation",
    "not_affected": "not_affected",
    "exploitable": "affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "false_positive": "not_affected",
}

# CycloneDX analysis.justification → OpenVEX justification. Lossy by design:
# three CycloneDX values collapse to vulnerable_code_cannot_be_controlled_by_adversary.
_CDX_JUST_TO_OPENVEX: dict[str, str] = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
    "protected_by_compensating_control": "inline_mitigations_already_exist",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}

_SUPPORTED_VEX_FORMATS: frozenset[str] = frozenset({"cyclonedx", "openvex"})


def _collect_sarif_rule_ids(run: dict[str, Any], ids: set[str], refs: dict[str, set[str]]) -> None:
    """Collect rule ids and their helpUri advisory references from one SARIF run."""

    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    if not isinstance(rules, list):
        return
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid.strip():
            continue
        rid = rid.strip()
        ids.add(rid)
        help_uri = rule.get("helpUri")
        if isinstance(help_uri, str) and help_uri.strip():
            refs.setdefault(rid, set()).add(help_uri.strip())


def _collect_sarif_result_ids(run: dict[str, Any], ids: set[str]) -> None:
    """Collect ruleId values from one SARIF run's results."""

    results = run.get("results") or []
    if not isinstance(results, list):
        return
    for r in results:
        if isinstance(r, dict):
            rid = r.get("ruleId")
            if isinstance(rid, str) and rid.strip():
                ids.add(rid.strip())


_UTF16_SARIF_REASON = (
    "Could not read SARIF: file is not valid UTF-8 (looks like UTF-16 or "
    "binary). Re-encode the SARIF as UTF-8; on Windows PowerShell use "
    "`osv-scanner ... | Out-File -Encoding utf8 osv-scanner.sarif.json` "
    "instead of `>` (which writes UTF-16)."
)


def _read_sarif_document(sarif_path: Path) -> tuple[dict[str, Any], str | None]:
    """Return (parsed SARIF document, error_or_None); ``{}`` whenever an error is returned.

    Every failure an ordinary bad file can produce — oversized, unreadable,
    wrongly encoded, unparseable, nested past the parser's stack — becomes a
    message the caller turns into exit 2. None of them is a defect in the kit, so
    none of them may reach the CLI's exit-3 handler.
    """

    oversize = oversize_reason(sarif_path, MAX_SARIF_BYTES, label="OSV-Scanner SARIF")
    if oversize is not None:
        return {}, oversize
    try:
        raw = sarif_path.read_text(encoding="utf-8")
    except OSError as exc:
        # bad_input_detail, never str(exc): the OSError repr carries the absolute
        # filename, which would ship the cwd / home directory / OS account name to
        # whoever the operator pastes the message to (M-002).
        return {}, f"Could not read SARIF '{sarif_path.name}': {bad_input_detail(exc)}."
    except UnicodeDecodeError:
        # UTF-16/UTF-32/binary input (e.g. Windows PowerShell `>` writes UTF-16).
        # UnicodeDecodeError is a ValueError, not an OSError, so it would escape to
        # the exit-3 handler; return a clean validation message instead (exit 2),
        # mirroring the UTF-8-BOM case which json.loads already reports cleanly.
        return {}, _UTF16_SARIF_REASON
    # Depth is checked before parsing, not left to RecursionError: CPython's C JSON
    # scanner exhausts the interpreter stack on a deeply nested document, and that
    # RecursionError is a RuntimeError — no `except` here caught it, so it escaped as
    # an exit-3 "Unexpected error". Shared with every other loader in the kit so one
    # problem has one explanation (input_limits.MAX_JSON_DEPTH).
    too_deep = too_deep_reason(raw, label=f"OSV-Scanner SARIF '{sarif_path.name}'")
    if too_deep is not None:
        return {}, too_deep
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {}, f"Could not parse SARIF JSON: {exc}"
    if not isinstance(doc, dict) or "runs" not in doc:
        return {}, "SARIF missing top-level 'runs' array."
    if not isinstance(doc.get("runs"), list):
        return {}, "SARIF 'runs' is not an array."
    return doc, None


def _collect_sarif_data(doc: dict[str, Any]) -> tuple[list[str], dict[str, list[str]]]:
    """Return (sorted unique vulnerability IDs, ID→advisory_url list) from a parsed SARIF.

    Deliberately tolerant: entries it cannot understand are skipped rather than
    refused, so a caller that only wants the IDs it *can* read still gets them.
    The strict gate lives in :func:`_validate_sarif_structure`, which the CLI runs
    first — tolerance here must never become silent acceptance there.
    """

    ids: set[str] = set()
    refs: dict[str, set[str]] = {}
    runs = doc.get("runs")
    for run in runs if isinstance(runs, list) else []:
        if not isinstance(run, dict):
            continue
        _collect_sarif_rule_ids(run, ids, refs)
        _collect_sarif_result_ids(run, ids)
    return sorted(ids), {rid: sorted(s) for rid, s in refs.items()}


def _extract_sarif_data(
    sarif_path: Path,
) -> tuple[list[str], dict[str, list[str]], str | None]:
    """Return (sorted unique vulnerability IDs, ID→advisory_url list, error_or_None).

    OSV-Scanner emits one rule per vulnerability (grouped by aliases) plus an
    optional ``helpUri`` per rule pointing to the OSV / GHSA / NVD advisory.
    We collect both per ID for ``--include-references``.
    """

    doc, err = _read_sarif_document(sarif_path)
    if err is not None:
        return [], {}, err
    ids, refs = _collect_sarif_data(doc)
    return ids, refs, None


# --- Structural validation of the INPUT SARIF -------------------------------
# Parallel to _validate_vex_structure / _validate_openvex_structure, which check the
# documents this command writes; this one checks the document it reads.
#
# Why it exists: `{"runs": [1, 2, 3]}` and `{"runs": [{"results": null}]}` are not
# SARIF, but the tolerant reader above skipped them silently and emit-vex published
# an empty VEX document at exit 0 — which a consumer reads as "the manufacturer
# scanned and has nothing to declare". A malformed scan must fail loudly instead.

#: Cap on the structural messages collected (and shown) for one document. A hostile
#: 20 MiB SARIF can hold millions of bad entries; naming ten of them is already
#: enough to fix the file, and collection stops there rather than building a list
#: proportional to the input.
_MAX_SARIF_STRUCTURE_ERRORS = 10


def _json_type_name(value: Any) -> str:
    """Name *value*'s JSON type the way the author of the SARIF would recognise it."""

    if isinstance(value, bool):  # bool is an int subclass; check it first
        return "a boolean"
    names: dict[type, str] = {
        type(None): "null",
        int: "a number",
        float: "a number",
        str: "a string",
        list: "an array",
        dict: "an object",
    }
    return names.get(type(value), "an unsupported value")


def _bad_element_errors(prefix: str, items: list[Any], budget: int) -> list[str]:
    """Up to *budget* messages naming the entries of *items* that are not objects."""

    if budget <= 0:
        return []
    bad = (
        f"{prefix}[{k}] must be an object, not {_json_type_name(item)}"
        for k, item in enumerate(items)
        if not isinstance(item, dict)
    )
    return list(islice(bad, budget))


def _validate_sarif_tool(i: int, run: dict[str, Any], budget: int) -> list[str]:
    """Structural messages for ``runs[i].tool``.

    An absent ``tool`` / ``driver`` / ``rules`` is accepted (OSV-Scanner always
    writes them, but a trimmed fixture legitimately may not). A field that is
    *present* with the wrong JSON type is not: that is a value the reader would
    silently drop.
    """

    node: Any = run
    for field, label in (("tool", f"runs[{i}].tool"), ("driver", f"runs[{i}].tool.driver")):
        if field not in node:
            return []
        node = node[field]
        if not isinstance(node, dict):
            return [f"{label} must be an object, not {_json_type_name(node)}"]
    if "rules" not in node:
        return []
    rules = node["rules"]
    if not isinstance(rules, list):
        return [f"runs[{i}].tool.driver.rules must be an array, not {_json_type_name(rules)}"]
    return _bad_element_errors(f"runs[{i}].tool.driver.rules", rules, budget)


def _validate_sarif_run(i: int, run: Any, budget: int) -> list[str]:
    """Structural messages for one ``runs[i]`` entry (empty when it is well formed)."""

    if not isinstance(run, dict):
        return [f"runs[{i}] must be an object, not {_json_type_name(run)}"]
    errs = _validate_sarif_tool(i, run, budget)
    if "results" not in run:
        return errs
    results = run["results"]
    if not isinstance(results, list):
        # Includes the explicit `"results": null` case: `run.get("results") or []`
        # read it as "this run found nothing", which is not what the file says.
        errs.append(f"runs[{i}].results must be an array, not {_json_type_name(results)}")
        return errs
    errs.extend(_bad_element_errors(f"runs[{i}].results", results, budget - len(errs)))
    return errs


def _validate_sarif_structure(doc: dict[str, Any], *, limit: int = _MAX_SARIF_STRUCTURE_ERRORS) -> list[str]:
    """Return up to *limit* structural-validation messages for a parsed SARIF document."""

    runs = doc.get("runs")
    if not isinstance(runs, list):
        return ["'runs' must be an array"]
    errs: list[str] = []
    for i, run in enumerate(runs):
        errs.extend(_validate_sarif_run(i, run, limit - len(errs)))
        if len(errs) >= limit:
            return errs[:limit]
    return errs


def _sarif_structure_error(sarif_path: Path, errors: list[str]) -> str:
    """Render the refusal for a structurally invalid input SARIF (basename only, M-002)."""

    return (
        f"OSV-Scanner SARIF '{markup_safe(sarif_path.name)}' is not a structurally valid SARIF document:\n  - "
        + "\n  - ".join(errors)
        + "\nRefusing to emit a VEX document from it: an empty or partial VEX reads to a "
        "consumer as 'the manufacturer has nothing to declare'. Re-run "
        "`osv-scanner --format sarif --recursive .` and keep its output verbatim."
    )


# Backwards-compatible shim retained for callers (and tests) that loaded
# `_extract_vuln_ids_from_sarif` from v0.1.
def _extract_vuln_ids_from_sarif(sarif_path: Path) -> tuple[list[str], str | None]:
    ids, _refs, err = _extract_sarif_data(sarif_path)
    return ids, err


def _build_vex_document(
    vuln_ids: list[str],
    source_path: Path,
    *,
    waivers: dict[str, _VulnWaiver] | None = None,
    references: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Construct a CycloneDX VEX 1.6 document with per-finding analysis.

    - Without a matching waiver: ``analysis.state = in_triage`` (default).
    - With a matching waiver: ``analysis.state = not_affected``, justification
      mapped to the CycloneDX enum when provided, free-text justification
      always copied to ``analysis.detail``.
    - With ``references`` mapping: advisory URLs (OSV record, GHSA page,
      etc.) are embedded as ``advisories[].url`` per CycloneDX VEX 1.6 shape.

    ``source_path`` is cited by basename only: a VEX document is published to
    downstream consumers, so the full ``--osv-sarif`` path would ship the
    producer's directory layout (and OS username) to every reader.
    """

    waivers = waivers or {}
    references = references or {}
    now = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    vulns: list[dict[str, Any]] = []
    for vid in vuln_ids:
        entry: dict[str, Any] = {"id": vid}
        urls = references.get(vid, [])
        if urls:
            entry["advisories"] = [{"url": u} for u in urls]
        w = waivers.get(vid)
        if w is None:
            entry["analysis"] = {
                "state": "in_triage",
                "detail": (
                    f"Imported from {source_path.name} by oss-policy-kit "
                    "emit-vex. Manufacturer analysis pending; fill in state, "
                    "justification, and response per CycloneDX VEX 1.6 vocabulary."
                ),
            }
        else:
            analysis: dict[str, Any] = {
                "state": "not_affected",
                "detail": w.justification_text,
            }
            if w.cdx_justification is not None:
                analysis["justification"] = w.cdx_justification
            entry["analysis"] = analysis
        vulns.append(entry)
    return {
        "bomFormat": _BOM_FORMAT,
        "specVersion": _VEX_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "oss-policy-kit",
                    "name": "oss-policy-kit emit-vex",
                    "version": _emit_vex_tool_version(),
                }
            ],
        },
        "vulnerabilities": vulns,
    }


def _build_openvex_statement(
    vid: str,
    *,
    waiver: _VulnWaiver | None,
    urls: list[str],
    product_id: str,
    source_path: Path,
) -> dict[str, Any]:
    """Build one OpenVEX ``statements[]`` entry for vulnerability ``vid``.

    - Without a matching waiver: ``status = under_investigation`` (the OpenVEX
      equivalent of CycloneDX ``in_triage``) plus a ``status_notes`` pointer.
    - With a matching waiver: ``status = not_affected``; the waiver's CycloneDX
      justification (when present) is mapped to the OpenVEX justification enum,
      and the free-text justification is always copied to ``impact_statement``
      so the OpenVEX rule "not_affected requires justification or
      impact_statement" is satisfied either way.
    - The first advisory URL (when ``--include-references`` collected one) is
      mapped to ``vulnerability.@id`` (OpenVEX carries a single canonical URI,
      not a CycloneDX-style advisories array).

    As on the CycloneDX side, ``source_path`` is cited by basename only so the
    published document does not disclose the producer's directory layout.
    """

    vuln_obj: dict[str, Any] = {"name": vid}
    if urls:
        vuln_obj["@id"] = urls[0]
    stmt: dict[str, Any] = {
        "vulnerability": vuln_obj,
        "products": [{"@id": product_id}],
    }
    if waiver is None:
        stmt["status"] = "under_investigation"
        stmt["status_notes"] = (
            f"Imported from {source_path.name} by oss-policy-kit emit-vex. "
            "Manufacturer analysis pending; set status, justification, and "
            "action/impact statements per the OpenVEX vocabulary."
        )
    else:
        stmt["status"] = "not_affected"
        mapped = _CDX_JUST_TO_OPENVEX.get(waiver.cdx_justification) if waiver.cdx_justification else None
        if mapped is not None:
            stmt["justification"] = mapped
        stmt["impact_statement"] = waiver.justification_text
    return stmt


def _build_openvex_document(
    vuln_ids: list[str],
    source_path: Path,
    *,
    waivers: dict[str, _VulnWaiver] | None = None,
    references: dict[str, list[str]] | None = None,
    product: str | None = None,
) -> dict[str, Any]:
    """Construct an OpenVEX (v0.2.0) document from the same inputs as the CycloneDX path.

    When ``product`` is omitted the placeholder ``pkg:generic/UNKNOWN`` is used
    (the caller is responsible for warning the operator). The ``@id`` and
    ``timestamp`` are time-derived via the SDE-honoring clock, so a pinned
    ``SOURCE_DATE_EPOCH`` yields byte-identical output (reproducible-build fence).
    """

    waivers = waivers or {}
    references = references or {}
    now = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    product_id = product if (product and product.strip()) else _OPENVEX_PRODUCT_PLACEHOLDER
    statements = [
        _build_openvex_statement(
            vid,
            waiver=waivers.get(vid),
            urls=references.get(vid, []),
            product_id=product_id,
            source_path=source_path,
        )
        for vid in vuln_ids
    ]
    return {
        "@context": _OPENVEX_CONTEXT,
        "@id": f"https://openvex.dev/docs/oss-policy-kit/{now}",
        "author": _OPENVEX_AUTHOR,
        "timestamp": now,
        "version": 1,
        "tooling": f"oss-policy-kit emit-vex {_emit_vex_tool_version()}",
        "statements": statements,
    }


def _validate_openvex_statement(i: int, s: Any) -> list[str]:
    """Structural-validation messages for one OpenVEX ``statements[i]`` entry."""

    if not isinstance(s, dict):
        return [f"statements[{i}] must be an object"]
    errs: list[str] = []
    vuln = s.get("vulnerability")
    if not isinstance(vuln, dict) or not isinstance(vuln.get("name"), str) or not vuln["name"].strip():
        errs.append(f"statements[{i}].vulnerability.name missing or empty")
    products = s.get("products")
    if not isinstance(products, list) or not products:
        errs.append(f"statements[{i}].products[] missing or empty")
    else:
        for j, p in enumerate(products):
            if not isinstance(p, dict) or not isinstance(p.get("@id"), str) or not p["@id"].strip():
                errs.append(f"statements[{i}].products[{j}].@id missing or empty")
    status = s.get("status")
    if status not in _OPENVEX_STATUSES:
        errs.append(f"statements[{i}].status={status!r} not in {sorted(_OPENVEX_STATUSES)}")
    if status == "not_affected":
        just = s.get("justification")
        impact = s.get("impact_statement")
        if just is None and not (isinstance(impact, str) and impact.strip()):
            errs.append(f"statements[{i}] status=not_affected requires justification or impact_statement")
        if just is not None and just not in _OPENVEX_JUSTIFICATIONS:
            errs.append(f"statements[{i}].justification={just!r} not in {sorted(_OPENVEX_JUSTIFICATIONS)}")
    if status == "affected" and not (isinstance(s.get("action_statement"), str) and s["action_statement"].strip()):
        errs.append(f"statements[{i}] status=affected requires action_statement")
    return errs


def _validate_openvex_structure(doc: dict[str, Any]) -> list[str]:
    """Return a list of OpenVEX structural-validation error messages (empty on success).

    Lightweight required-field / enum check against the OpenVEX v0.2.0 shape —
    parallel to ``_validate_vex_structure`` for CycloneDX. Does not bundle the
    full OpenVEX JSON Schema.
    """

    errs: list[str] = []
    if doc.get("@context") != _OPENVEX_CONTEXT:
        errs.append(f"@context must be {_OPENVEX_CONTEXT!r}; got {doc.get('@context')!r}")
    for field in ("@id", "author", "timestamp"):
        value = doc.get(field)
        if not isinstance(value, str) or not value.strip():
            errs.append(f"{field} missing or empty")
    if doc.get("version") != 1:
        errs.append(f"version must be 1; got {doc.get('version')!r}")
    statements = doc.get("statements", [])
    if not isinstance(statements, list):
        errs.append("statements[] must be an array")
        return errs
    for i, s in enumerate(statements):
        errs.extend(_validate_openvex_statement(i, s))
    return errs


# CycloneDX VEX 1.6 structural validation errors that --validate surfaces.
_CDX_ALLOWED_STATES: frozenset[str] = frozenset(
    {"resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive", "not_affected"}
)


def _validate_vex_structure(doc: dict[str, Any]) -> list[str]:
    """Return a list of structural-validation error messages (empty on success).

    Lightweight CycloneDX VEX 1.6 contract check — does NOT replace
    schema validation against the official CycloneDX JSON Schema, but
    catches the common errors (missing required fields, unknown enum
    values) without bundling the full schema.
    """

    errs: list[str] = []
    if doc.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be 'CycloneDX'")
    if doc.get("specVersion") != "1.6":
        errs.append(f"specVersion must be '1.6'; got {doc.get('specVersion')!r}")
    if doc.get("version") != 1:
        errs.append(f"version must be 1; got {doc.get('version')!r}")
    vulns = doc.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        errs.append("vulnerabilities[] must be an array")
        return errs
    for i, v in enumerate(vulns):
        errs.extend(_validate_vex_vuln(i, v))
    return errs


def _validate_vex_vuln(i: int, v: Any) -> list[str]:
    """Structural-validation messages for one ``vulnerabilities[i]`` entry."""

    if not isinstance(v, dict):
        return [f"vulnerabilities[{i}] must be an object"]
    errs: list[str] = []
    if not isinstance(v.get("id"), str) or not v["id"].strip():
        errs.append(f"vulnerabilities[{i}].id missing or empty")
    analysis = v.get("analysis")
    if not isinstance(analysis, dict):
        errs.append(f"vulnerabilities[{i}].analysis missing")
        return errs
    state = analysis.get("state")
    if state not in _CDX_ALLOWED_STATES:
        errs.append(f"vulnerabilities[{i}].analysis.state={state!r} not in {sorted(_CDX_ALLOWED_STATES)}")
    justification = analysis.get("justification")
    if justification is not None and justification not in _CDX_JUSTIFICATIONS:
        errs.append(
            f"vulnerabilities[{i}].analysis.justification={justification!r} not in {sorted(_CDX_JUSTIFICATIONS)}"
        )
    return errs


def _emit_vex_tool_version() -> str:
    """Return the kit's version string for embedding in the VEX metadata."""

    try:
        from oss_policy_kit import __version__ as v  # noqa: PLC0415

        return str(v)
    except ImportError:  # pragma: no cover - defensive
        return "unknown"


def _write_vex_output(
    payload: str,
    output: Path,
    vuln_ids: list[str],
    vuln_waivers: dict[str, _VulnWaiver],
    *,
    doc_label: str = "CycloneDX VEX 1.6",
) -> None:
    """Write the VEX document to ``output`` and report applied / unmatched waivers on stderr."""

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
    except OSError as exc:
        raise InvalidInputError(f"Cannot write to --output '{output}': {exc}") from exc
    applied = sum(1 for vid in vuln_ids if vid in vuln_waivers)
    stderr_console().print(
        f"[green]Wrote {doc_label} document[/green]: "
        f"{output} ({len(vuln_ids)} vulnerability ID(s), "
        f"{applied} marked not_affected via waivers)."
    )
    # Report waiver IDs that did NOT match any SARIF finding so the user can spot
    # typos, stale waivers, or alias mismatches (e.g. waiver lists CVE-2024-XYZ but
    # SARIF carries GHSA-aaa).
    sarif_ids = set(vuln_ids)
    unmatched_waivers = [vid for vid in vuln_waivers if vid not in sarif_ids]
    if unmatched_waivers:
        preview = ", ".join(sorted(unmatched_waivers)[:10])
        more = f" (+{len(unmatched_waivers) - 10} more)" if len(unmatched_waivers) > 10 else ""
        stderr_console().print(
            f"[yellow]Warning:[/yellow] {len(unmatched_waivers)} waiver "
            f"vulnerability_id(s) did not match any SARIF finding: "
            f"{preview}{more}. Check for typos or alias mismatches "
            f"(CVE vs GHSA vs OSV vs RUSTSEC)."
        )


def _explicit_waivers_warning(waivers: Path) -> str | None:
    """Warn when a user-supplied ``--waivers`` path cannot be a waivers file.

    An absent DEFAULT ``waivers/waivers.yaml`` is an ordinary repository state, so it
    stays silent. A path the operator typed is different: a one-character typo (or a
    directory) was indistinguishable from "this project has no waivers", and the
    command still exited 0 having published a document in which every waived finding
    silently reverted to ``in_triage`` / ``under_investigation``. Every *other*
    bad-waivers case already warns; this was the one silent branch.

    The path is echoed exactly as typed and never resolved, so a relative argument
    cannot become an absolute one that ships the operator's home directory or account
    name to whoever the message is pasted to (M-002).
    """

    if waivers.is_file():
        return None
    what = "is a directory, not a file" if waivers.is_dir() else "does not exist"
    # markup_safe: the path is printed inside a Rich markup string, and Rich silently
    # drops anything shaped like `[tag]` -- the one token the operator has to compare
    # against what they typed is exactly the token that must survive rendering.
    return (
        f"--waivers path '{markup_safe(waivers)}' {what}; no waivers were applied, so every "
        "finding is emitted as unanalyzed (CycloneDX state 'in_triage' / OpenVEX "
        "status 'under_investigation'). Check the path for a typo."
    )


def _read_validated_sarif(osv_sarif: Path) -> tuple[list[str], dict[str, list[str]]]:
    """Read ``--osv-sarif`` and refuse (exit 2) anything that is not a valid SARIF document.

    Structure is checked BEFORE the IDs are collected, because the tolerant reader
    turns a malformed scan into an empty ID list, and an empty VEX document at exit 0
    reads to a downstream consumer as a clean bill of health.
    """

    if not osv_sarif.is_file():
        raise InvalidInputError(
            f"OSV-Scanner SARIF not found at {osv_sarif}. Run "
            "`osv-scanner --format sarif --recursive . > "
            f"{osv_sarif.as_posix()}` first."
        )
    sarif_doc, err = _read_sarif_document(osv_sarif)
    if err is not None:
        raise InvalidInputError(err)
    structure_errors = _validate_sarif_structure(sarif_doc)
    if structure_errors:
        raise InvalidInputError(_sarif_structure_error(osv_sarif, structure_errors))
    return _collect_sarif_data(sarif_doc)


def _load_and_report_waivers(waivers: Path, *, explicit: bool) -> dict[str, _VulnWaiver]:
    """Load vulnerability-keyed waivers, printing every reason none of them applied."""

    path_warning = _explicit_waivers_warning(waivers) if explicit else None
    if path_warning is not None:
        # Warned, not refused -- deliberately, and this is the weaker of the two remedies.
        #
        # `evaluate` and `correlate-findings` exit 2 for an unusable explicit --waivers,
        # and this surface publishes its output, so exit 2 is the better end state. It is
        # not a patch-release change: turning exit 0 into exit 2 breaks anyone who points
        # --waivers at a path that does not exist as a way of saying "no waivers", and
        # this repository's own test suite does exactly that in four places, which is as
        # clear a signal as there is that adopters do too.
        #
        # The defect was the SILENCE: a one-character typo flipped every waived finding
        # back to in_triage with nothing on stdout or stderr. That is fixed here. The exit
        # code belongs in the next minor, with a note in the migration guide.
        stderr_console().print(f"[yellow]Waiver warning:[/yellow] {markup_safe(path_warning)}")
    vuln_waivers, waiver_warnings = _load_vuln_waivers(waivers)
    for w in waiver_warnings:
        stderr_console().print(f"[yellow]Waiver warning:[/yellow] {markup_safe(w)}")
    return vuln_waivers


def _run_emit_vex(
    osv_sarif: Path,
    output: Path | None,
    waivers: Path,
    *,
    validate_output: bool,
    include_references: bool,
    output_format: str = "cyclonedx",
    product: str | None = None,
    waivers_explicit: bool = False,
) -> None:
    """Core emit-vex flow shared by the Typer command (raises OssPolicyKitError on bad input).

    ``waivers_explicit`` says the operator typed ``--waivers`` rather than falling back
    to the default location; it is what makes a missing file worth a warning.
    """

    if output_format not in _SUPPORTED_VEX_FORMATS:
        raise InvalidInputError(
            f"Unknown --format {output_format!r}; expected one of {sorted(_SUPPORTED_VEX_FORMATS)}."
        )
    vuln_ids, refs = _read_validated_sarif(osv_sarif)
    vuln_waivers = _load_and_report_waivers(waivers, explicit=waivers_explicit)
    refs_arg = refs if include_references else None

    if output_format == "openvex":
        if not (product and product.strip()):
            stderr_console().print(
                f"[yellow]Warning:[/yellow] no --product supplied; emitting placeholder product "
                f"@id '{_OPENVEX_PRODUCT_PLACEHOLDER}'. The OpenVEX document is structurally valid "
                "but you must set a real product identifier (e.g. a purl) before distributing it."
            )
        doc = _build_openvex_document(
            vuln_ids, osv_sarif, waivers=vuln_waivers or None, references=refs_arg, product=product
        )
        if validate_output:
            errors = _validate_openvex_structure(doc)
            if errors:
                raise InvalidInputError("OpenVEX structural validation failed:\n  - " + "\n  - ".join(errors))
        doc_label = "OpenVEX"
    else:
        doc = _build_vex_document(vuln_ids, osv_sarif, waivers=vuln_waivers or None, references=refs_arg)
        if validate_output:
            errors = _validate_vex_structure(doc)
            if errors:
                raise InvalidInputError("CycloneDX VEX 1.6 structural validation failed:\n  - " + "\n  - ".join(errors))
        doc_label = "CycloneDX VEX 1.6"

    payload = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    if output is None:
        write_stdout_text(payload)
    else:
        _write_vex_output(payload, output, vuln_ids, vuln_waivers, doc_label=doc_label)


def _flag_was_provided(ctx: typer.Context, name: str) -> bool:
    """Return True when the operator passed CLI option *name* (not the typer default).

    Twin of ``cli.evaluate._flag_was_provided``; kept local because importing that
    module here would register its commands ahead of this one and reorder ``--help``.
    Compared by enum ``name`` rather than by importing ``ParameterSource``: Typer
    vendors its own Click, so the class imported from top-level ``click`` can be a
    different object than the one the runtime returns.
    """

    try:
        source = ctx.get_parameter_source(name)
    except Exception:  # noqa: BLE001 - provenance is best-effort; never crash the CLI
        return False
    return source is not None and getattr(source, "name", "") != "DEFAULT"


@app.command("emit-vex", rich_help_panel=CMD_PANEL_EXPORT)
def emit_vex_cmd(
    ctx: typer.Context,
    osv_sarif: Path = typer.Option(
        _DEFAULT_OSV_SARIF,
        "--osv-sarif",
        help=(
            "Path to OSV-Scanner SARIF output. Defaults to "
            ".oss-policy-kit/evidence/sast/osv-scanner.sarif.json (the path "
            "SAST-OSV-068 consumes)."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the VEX document. Omit for stdout.",
    ),
    output_format: str = typer.Option(
        "cyclonedx",
        "--format",
        help=(
            "VEX output format: 'cyclonedx' (CycloneDX VEX 1.6, default) or "
            "'openvex' (OpenVEX v0.2.0). The default is unchanged for backward "
            "compatibility."
        ),
    ),
    product: str | None = typer.Option(
        None,
        "--product",
        help=(
            "Product identifier (e.g. a purl like pkg:pypi/acme@1.2.3) used as the "
            "OpenVEX statements[].products[].@id. OpenVEX only. When omitted, a "
            "placeholder @id is emitted with a warning; ignored for --format cyclonedx."
        ),
    ),
    waivers: Path = typer.Option(
        _DEFAULT_WAIVERS,
        "--waivers",
        help=(
            "Path to waivers/waivers.yaml. Entries carrying a "
            "vulnerability_ids: [...] field auto-populate analysis.state=not_affected "
            "for matching findings. Control-keyed waivers are ignored by emit-vex."
        ),
    ),
    validate_output: bool = typer.Option(
        False,
        "--validate/--no-validate",
        help=(
            "Structural validation against the CycloneDX VEX 1.6 required-field "
            "set. Lightweight — does not bundle the full CycloneDX JSON Schema. "
            "Errors exit 2."
        ),
    ),
    include_references: bool = typer.Option(
        False,
        "--include-references/--no-include-references",
        help=("Embed advisory URLs from OSV-Scanner SARIF rule helpUri into vulnerabilities[].advisories[]."),
    ),
) -> None:
    """Emit a VEX document from OSV-Scanner SARIF (CycloneDX VEX 1.6 or OpenVEX).

    Findings without a matching waiver are emitted as ``in_triage``
    (CycloneDX) / ``under_investigation`` (OpenVEX). Findings matched by a
    waiver carrying ``vulnerability_ids: [...]`` get ``not_affected`` plus the
    waiver's justification text, with the ``vex_justification`` enum mapped to
    the chosen format's vocabulary. ``--format`` defaults to ``cyclonedx``;
    ``--format openvex`` accepts ``--product`` for the OpenVEX product identity.
    """

    try:
        _run_emit_vex(
            osv_sarif,
            output,
            waivers,
            validate_output=validate_output,
            include_references=include_references,
            output_format=output_format,
            product=product,
            waivers_explicit=_flag_was_provided(ctx, "waivers"),
        )
    except OssPolicyKitError as exc:
        stderr_console().print(f"[red]Error:[/red] {markup_safe(exc.message)}")
        raise typer.Exit(code=2) from exc
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        stderr_console().print(f"[red]Unexpected error:[/red] {markup_safe(exc)}")
        raise typer.Exit(code=3) from exc
