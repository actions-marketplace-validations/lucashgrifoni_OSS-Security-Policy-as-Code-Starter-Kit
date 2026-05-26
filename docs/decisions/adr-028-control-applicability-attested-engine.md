# ADR-028 - Formalize the applicability engine and activate the ATTESTED state (v8.0.0)

- **Status**: proposed (targets v8.0.0, BREAKING) — pending maintainer ratification (roadmap plan §11.2, §11.3)
- **Date**: 2026-05-25
- **Context window**: v8.x roadmap horizon — "Gemara & OSPS conformance alignment"
- **Related**: ADR-013 (reports/2.0 five-state vocabulary), ADR-027 (default flip), ADR-018 (OSPS Baseline 2026 / Scorecard v6), ADR-017 (source-built container release / cosign), `ROADMAP.md`

## Context

The `reports/2.0` vocabulary (ADR-013) defines five states, but the engine today only
ever populates four of them:

- `NOT_APPLICABLE` **already exists and is widely emitted** — individual evaluators
  return it when a precondition is absent (e.g. no Dockerfile, no cloud config), and
  `engine.py` excludes it from scoring (`_SCORING_EXCLUDED`). Applicability is real but
  **ad hoc**: the precondition lives inside each `eval_*` function and is neither
  declared in control metadata nor inspectable/queryable.
- `ATTESTED` is in the contract vocabulary but is **never produced** by any evaluator.
  There is no attestation-driven path that resolves a non-automatable, evidence-backed
  control to `ATTESTED`.

Meanwhile OpenSSF Scorecard v6 (PR #4952) is standardizing exactly this: a conformance
output over `PASS / FAIL / UNKNOWN / NOT_APPLICABLE / ATTESTED`, an applicability engine
that detects preconditions, and an **attestation mechanism for non-automatable
controls**, aligned to the Gemara Layer-4 "pivot point". For the kit to remain the
interoperable local-first node it positions as, its grading model should converge on
that semantics rather than diverge.

Two changes here are breaking: (1) activating `ATTESTED` adds a state that existing
gate consumers must handle; (2) formalizing applicability can move some controls from
`FAIL` to `NOT_APPLICABLE`, which changes pass/fail outcomes for existing profiles.
Both require a major bump and a staged rollout.

## Decision

In **v8.0.0**, formalize applicability and activate `ATTESTED`:

1. **Declared preconditions.** Move each control's applicability from implicit
   in-function logic to a declared, inspectable precondition in control metadata
   (e.g. "requires a container build file", "requires a cloud CI config"). The engine
   evaluates the precondition first; a control whose precondition is unmet resolves to
   `NOT_APPLICABLE` consistently and visibly, instead of each evaluator deciding ad hoc.
2. **`ATTESTED` activation.** A non-automatable, evidence-backed control resolves to
   `ATTESTED` when a verifiable attestation is present (in-toto statement verified with
   cosign keyless, reusing the release-hardening track from ADR-017), rather than
   collapsing to a plain `PASS`. `ATTESTED` is distinguished from `PASS` in reports.
3. **OSPS-style conformance output** is offered alongside the report contract, mapping
   the kit's states to the OSPS conformance shape.
4. **Staged rollout.** Ships **opt-in** behind a flag for at least one minor cycle;
   becomes default only once Scorecard v6 / Gemara reach GA (today they are PR/draft),
   so the kit does not freeze semantics against a moving upstream.

Assurance honesty (a core non-goal guard) is preserved: `ATTESTED` requires a verified
attestation, never a self-claim; `NOT_APPLICABLE` never inflates a pass.

## Alternatives considered

1. **Leave applicability ad hoc and never emit `ATTESTED`.** Rejected — `ATTESTED` is
   already promised by the contract vocabulary but dead; and ad-hoc preconditions are
   not inspectable, which blocks the conformance/Gemara story.
2. **Emit `ATTESTED` for any evidence-backed pass.** Rejected — would equate
   "evidence present" with "attestation verified", breaking assurance honesty.
3. **Switch the default immediately at v8.0.0.** Rejected — upstream (Scorecard v6,
   Gemara) is not GA; opt-in first avoids freezing against a draft spec.
4. **Skip the conformance output.** Rejected — it is the concrete interoperability
   deliverable that lets the kit's results feed the OpenSSF GRC ecosystem.

## Consequences

- Applicability becomes declared and inspectable; `NOT_APPLICABLE` resolution is
  consistent across families instead of per-evaluator.
- `ATTESTED` becomes a live, verifiable state — the kit can show *which* controls are
  backed by a verified attestation versus a deterministic pass.
- Some profiles' pass/fail outcomes shift as controls move `FAIL` → `NOT_APPLICABLE`;
  documented as breaking with a migration note and a diff of affected controls.
- The kit speaks Scorecard-v6 / Gemara-Layer-4 conformance semantics, reinforcing the
  "interoperable node, not competitor" positioning.
- Trade-off: precondition metadata must be authored per control; depends on ADR-027
  having made `reports/2.0` the default first.

## References

- OpenSSF Scorecard v6 / OSPS conformance + Gemara Layer 4 — <https://github.com/ossf/scorecard/pull/4952>, <https://openssf.org/blog/2026/03/09/introducing-the-gemara-model/>
- OSPS Baseline — <https://baseline.openssf.org/>
- ADR-013, ADR-017, ADR-018; `ROADMAP.md` (v8.x horizon); roadmap plan §6, §11.2–11.3
