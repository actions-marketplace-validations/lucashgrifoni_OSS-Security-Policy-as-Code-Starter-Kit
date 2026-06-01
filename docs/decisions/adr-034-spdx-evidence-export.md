# ADR-034 - SPDX evidence export (`export-evidence --format spdx`, v7.0.0)

- **Status**: accepted (targets v7.0.0, ADDITIVE / non-breaking) — 2026-06-01
- **Date**: 2026-06-01
- **Context window**: v7.x roadmap horizon — "Contract modernization & ecosystem interoperability"
- **Related**: ADR-012 (`export-evidence` registry), ADR-002 (`emit-vex` CycloneDX scope), ADR-031 (OpenVEX), `docs/evidence-export.md`, roadmap plan §3.8/§6 (v7.x)

## Context

`export-evidence` already renders the evaluation report into a format registry
(`chainloop`, `sarif`; ADR-012). The roadmap (§3.8/§6 v7.x) calls for SPDX parity alongside
the CycloneDX-flavoured outputs the kit already produces, because compliance- and
licensing-driven adopters standardise on SPDX.

The honesty trap: SPDX is fundamentally a **software bill of materials** describing components,
licenses, and relationships. The kit is a **clone-only policy evaluator**, not a dependency
resolver — building a real component SBOM of the target is a scanner's job and is an explicit
non-goal (guard-rail §5.2: the kit composes/exports, it does not become a scanner).

## Decision

Add `spdx` to the `export-evidence` registry as an **SPDX 2.3 (JSON) evidence document**, not a
dependency SBOM. It describes exactly one package element — the evaluated repository — and
attaches the policy-evaluation result as SPDX **annotations** (one per control: control id,
status, assurance grade) plus document-level creator/tool metadata (`Tool: oss-policy-kit-<ver>`).

- **Target format: SPDX 2.3 JSON.** SPDX 2.3 is stable and widely consumed; SPDX 3.0's
  element/linked-data model is deferred until it is GA and an adopter needs it (guard-rail §6:
  promote on GA dependency, not on announcement). The renderer emits a `spdxVersion: "SPDX-2.3"`
  document.
- **Renderer + `--validate`.** Implemented as `_render_spdx(report)` plugged into `_RENDERERS`;
  `--validate` checks the required SPDX 2.3 fields (`spdxVersion`, `SPDXID`, `creationInfo`,
  `name`, `documentNamespace`, at least one `packages` entry).
- **Explicit scope caveat in output + docs.** The document's `comment` field and
  `docs/evidence-export.md` state plainly: this is a *policy-evaluation evidence projection*
  expressed in SPDX, **not** a dependency/component SBOM of the target.

## Alternatives considered

1. **Build a real dependency SBOM in SPDX.** Rejected — requires dependency resolution; that is
   a scanner's job and an explicit non-goal. The kit composes scanner output, it does not
   produce it.
2. **SPDX 3.0 JSON-LD now.** Rejected for v7.0.0 — the 3.0 model is significantly more complex
   and still churning in adoption; start conservative on 2.3, revisit 3.0 additively on GA + demand.
3. **SPDX tag-value (`.spdx`) instead of JSON.** Rejected — JSON matches the registry's existing
   JSON-document shape and is easier to validate; tag-value can follow if an adopter needs it.

## Consequences

- SPDX-standardised adopters get a parseable evidence artifact from the same evaluation run.
- The kit gains SBOM-ecosystem format parity (CycloneDX VEX via `emit-vex`, SPDX evidence via
  `export-evidence`) without crossing into scanner territory.
- Trade-off: one more renderer + validation path + golden fixture to maintain; bounded by the
  single-package, annotation-based shape.

## References

- [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/)
- ADR-012 (`export-evidence` registry), ADR-031 (OpenVEX export — sibling interop additive)
- `src/oss_policy_kit/cli/export_evidence.py` (`_RENDERERS`, `_SUPPORTED_FORMATS`, `_validate`)
- `docs/evidence-export.md`; roadmap plan §3.8/§6
