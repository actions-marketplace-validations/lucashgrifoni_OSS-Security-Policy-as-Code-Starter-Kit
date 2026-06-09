# ADR-037 - OSPS Baseline v2026.02.19 coverage map (structured + generated)

- **Status**: accepted (v7.2.0)
- **Date**: 2026-06-09
- **Related**: ADR-018 (osps-baseline-2026-1 + Scorecard v6), ADR-028 (control assurance/states)

## Context

The kit ships the `osps-baseline-2026-1` profile (ADR-018) mapping 18 bundled
controls to the four OSPS *areas*. `docs/osps-mapping.md` additionally carries a
hand-authored Starter/Advanced/Mature ladder. Neither is per **criterion** nor
pinned to the real OSPS criterion IDs (`OSPS-AC-01` …), and both are
hand-maintained — they drift when the catalog or profile changes.

Adopters coming from the OpenSSF OSPS Baseline want to navigate from a specific
criterion and maturity level (L1/L2/L3) to the concrete kit control that speaks
to it, and — just as importantly — to see *honestly what the kit does not cover*.

## Decision

Add a single, structured source of truth and generate the coverage view from it:

1. **Data file** `src/oss_policy_kit/data/frameworks/osps-baseline-2026.yaml` —
   the 41 OSPS Baseline **v2026.02.19** criteria (id, family, applicable levels,
   objective) transcribed from the signed upstream tag, plus a conservative
   `control -> criterion` signal map. Per-control assurance is **not** stored
   here; it is read live from the control catalog to avoid drift.
2. **Generator** `scripts/generate-osps-coverage.py` renders
   `docs/osps-baseline-2026-coverage.md`: an honest per-level coverage table
   (criteria in level / with kit signal / not yet expressed), a full
   per-criterion map with assurance, and an explicit gaps section. It validates
   data integrity (every mapping references a real catalog control that is a
   member of the profile, and a real criterion) and supports `--check`.
3. **Anti-overclaim contract.** Coverage means "a bundled control provides a
   clone-visible *signal toward* this criterion", never "satisfies" or
   "guarantees OSPS level N". A test asserts the honest framing and bans
   over-claim phrasing.

This is additive and advisory-only; it changes no control results, no report
schema, and no CLI contract.

## Alternatives considered

1. **Hand-author another level table in `osps-mapping.md`.** Rejected — it would
   duplicate existing prose and keep drifting; the value is a generated,
   integrity-checked artifact.
2. **Store the OSPS criterion → level data inside the profile YAML.** Rejected —
   the profile is a control list; criterion/level snapshot data and the signal
   map are a framework concern and belong in a `frameworks/` data file that can
   be pinned and re-mapped deliberately.
3. **Ship a Scorecard-v6 `--format=osps` conformance *verdict* renderer now.**
   Deferred — that wire format is still pre-GA (PR #4952). `OSPS-SCORECARD-V6-001`
   already consumes the verdict as evidence; the renderer waits for GA (ADR-018).

## Consequences

- Adopters get a pinned, per-criterion, per-level coverage view with real gaps
  shown (DO and SA families are 0% by design — the kit does not assess user-doc
  quality or threat modeling from a clone).
- Coverage cannot silently inflate: the per-level counts are pinned by tests, so
  adding a weak mapping fails CI.
- The OSPS Baseline is a rolling release; the data file pins a snapshot tag so a
  future re-map (a new `osps-baseline-YYYY-*`) is a deliberate change.

## References

- OSPS Baseline `v2026.02.19` (baseline.openssf.org; ossf/security-baseline tag
  `v2026.02.19`, signed), Scorecard v6 PR #4952
- `docs/osps-baseline-2026-coverage.md` (generated), `docs/osps-mapping.md`
