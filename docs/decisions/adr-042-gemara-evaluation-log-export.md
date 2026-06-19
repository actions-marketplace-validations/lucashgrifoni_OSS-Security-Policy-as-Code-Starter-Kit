# ADR-042 — Gemara Layer 5 Evaluation Log export format

- **Status:** accepted (v8.1.0)
- **Date:** 2026-06-19
- **Related:** ADR-034 (SPDX evidence export), ADR-036 (OSCAL + in-toto export GA), ADR-012 (export-evidence format registry)

## Context

The OpenSSF **Gemara** model is a Governance/Risk/Compliance engineering model with a layered
schema. **Layer 5** is the *Evaluation Log* — the artifact a conformance **gate** tool emits after
inspecting code, configurations, and deployments against controls. `oss-policy-kit` is exactly such
a gate (clone-only, deterministic), so a first-class Gemara Layer 5 projection lets the kit
interoperate with the broader Gemara GRC tooling (other layers, SARIF conversion via `go-gemara`,
etc.) — squarely on the kit's "compose + interoperate with ecosystem formats" thesis.

The Gemara schema is expressed in **CUE** and is **pre-1.0** (model `v0.17.0-dev` at time of writing;
the `evaluationlog` schema itself is marked `stable`). Adding a CUE toolchain dependency to validate
against it is explicitly out of scope (it would couple the kit to a pre-1.0 toolchain for no user
value — see README non-goals and the v8.1.0 scope-gate).

## Decision

Add `gemara` to the `export-evidence` format registry (ADR-012), alongside `spdx`/`oscal`/
`in-toto-bundle`:

- Each `ControlResult` maps to a Gemara `#ControlEvaluation` carrying one `#AssessmentLog`. The kit
  state maps to the Gemara `#Result` enum (`PASS`→`Passed`, `FAIL`→`Failed`,
  `UNKNOWN`/`MANUAL_REVIEW_REQUIRED`→`Needs Review`, `NOT_APPLICABLE`→`Not Applicable`,
  `ATTESTED`→`Passed`); the kit assurance grade maps to the Gemara `#ConfidenceLevel`
  (`deterministic`/`evidence-backed`/`attested`→`High`, `signal`→`Medium`). The top-level `result`
  is the worst-case aggregate.
- The targeted Gemara model version is **pinned** in the emitted `metadata.gemara-version`
  (`v0.17.0-dev`); the renderer honours the schema's `requirement.reference-id == control.reference-id`
  constraint.
- Validation is **structural** (the `_validate_gemara` registry validator), consistent with every
  other export format. **No CUE dependency** and no vendored CUE validator are added.

## Consequences

- Additive and backward-compatible: a new opt-in output format; no existing format, profile, control,
  or `evaluate` verdict changes. Ships in the v8.1.0 minor.
- Unsigned and structurally validated only. If the Gemara schema reaches 1.0 and an adopter needs
  strict schema conformance, a follow-up can pin a stable version and add validation then.
- The kit is positioned as a Gemara Layer 5 node without taking on any other Gemara layer (it does
  **not** author the Layer 2 control catalog in CUE/Gemara — that was rejected in the v8.1.0
  scope-gate as toolchain coupling with no user value).
