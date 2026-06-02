# ADR-035 - CEL / Rego policy export (`export-policy`, v7.0.0)

- **Status**: accepted (targets v7.0.0, ADDITIVE / non-breaking) — 2026-06-01
- **Date**: 2026-06-01
- **Context window**: v7.x roadmap horizon — "Contract modernization & ecosystem interoperability"
- **Related**: ADR-012 (`export-evidence` registry), roadmap plan §3.12/§6 (v7.x); OPA/Conftest, Kyverno, Chainloop, CEL

## Context

The roadmap (§3.12/§6 v7.x) calls for exporting a profile as CEL and/or Rego so the kit can
**feed** the policy engines the ecosystem already runs (OPA/Conftest, Kyverno, Chainloop) rather
than competing as an engine (guard-rail §5.2). This differs from `export-evidence`: it renders
the **profile + catalog** (the policy *definition*), not a prior evaluation *report*. Folding it
into `export-evidence` (which loads a report) would muddy that command's contract.

The fidelity trap: the kit's evaluators are richer than a static CEL/Rego rule can express
(they read files, parse workflows, project scanner SARIF). A generated rule cannot reproduce
that. Pretending otherwise would be dishonest.

## Decision

Add a **new dedicated subcommand** `oss-policy-kit export-policy --format {rego,cel}` that
renders a profile into a **best-effort policy skeleton** for the chosen engine, with fidelity
limits stated explicitly.

- **Source = profile + catalog**, not a report. Input: `--profile <id>` (+ optional
  `--kit-root`). Output: a `.rego` (package `osspolicykit`) or `.cel` rule set, one rule per
  control id, asserting "evidence for control X is present/passing".
- **Honest fidelity boundary.** Each generated file carries a header comment: the rules check
  **input the caller supplies** (e.g. a prior `evaluation-report.json` fed into OPA), they do
  **not** re-implement the kit's file/workflow/SARIF analysis. The export is an integration
  shim, not a reimplementation. This boundary is the core of the ADR.
- **Generated, read-only, deterministic.** Stable ordering by control id; no network; byte-stable.
- **`--validate`** runs a lightweight syntactic check (balanced blocks / package header present);
  deep semantic validation is the target engine's job (`opa check`, `conftest verify`).

## Alternatives considered

1. **Fold into `export-evidence --format rego`.** Rejected — `export-evidence` consumes a report;
   policy export consumes a profile. Different inputs → different subcommand keeps both contracts clean.
2. **Generate rules that re-implement evaluation in Rego.** Rejected — impossible to keep faithful
   to 212 evaluators and would create a second, drifting source of truth. The shim checks
   kit-produced input instead.
3. **CEL only (skip Rego) or Rego only.** Rejected — OPA/Conftest (Rego) and Kyverno/CEL are both
   common; support both via one `--format` switch, sharing the per-control iteration.

## Consequences

- Adopters can wire kit profiles into OPA/Conftest/Kyverno pipelines as a generated gate shim.
- The kit stays a generator, never an engine (guard-rail preserved).
- Trade-off: a new subcommand surface (validated by `cli-api-ui-contract-validator`) + two
  renderers + golden fixtures; bounded by the per-control skeleton shape and the explicit
  fidelity disclaimer.

## References

- [OPA / Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) · [CEL](https://github.com/google/cel-spec) · [Conftest](https://www.conftest.dev/) · [Kyverno](https://kyverno.io/)
- ADR-012 (`export-evidence`); roadmap plan §3.12/§6
- `src/oss_policy_kit/cli/` (new `export_policy.py`, registered on the shared Typer `app`)
