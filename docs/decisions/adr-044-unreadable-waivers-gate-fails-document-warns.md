# ADR-044 — An unreadable `--waivers` path fails a gate and warns a document

- **Status**: accepted — ratified 2026-08-07
- **Date**: 2026-08-07
- **Related**: ADR-002 (`emit-vex` scope), the v10.0.7 clean-room fix `6658a60` that made the silent branch warn

## Context

Three commands accept `--waivers`: `evaluate`, `correlate-findings`, and `emit-vex`. When the
path the operator typed cannot be read — a one-character typo, or a directory — they do not
behave the same way:

| Command | Exit | Behaviour |
|---|---:|---|
| `evaluate` | **2** | `Waivers file not found: <path>` |
| `correlate-findings` | **2** | `--waivers <path> is not a file.` |
| `emit-vex` | **0** | `Waiver warning: … does not exist; no waivers were applied …`, and still writes the document |

The `emit-vex` behaviour was itself the *fix* for a real defect: before `6658a60` that branch
was **silent**, so a typo was indistinguishable from "this project has no waivers" and the
published VEX quietly downgraded every waived finding to `in_triage`. Warning was the chosen
remedy; exiting non-zero was not.

That left the kit with one flag, one error condition, and two contracts — discoverable only by
reading a docstring in `cli/emit_vex.py`. An internal defect register subsequently recorded the
difference as a bug (`DEF-001`, "emit-vex should exit 2"), which is the sign that the reasoning
was not written down anywhere a reader would find it.

## Decision

**Keep the asymmetry. It is principled, not accidental.** The deciding factor is what each
command produces, not which flag it accepts:

- **`evaluate` and `correlate-findings` produce a verdict.** A gate that cannot read its waivers
  produces verdicts that are *factually wrong*: controls the operator legitimately dispensed are
  reported as failing. There is no honest document to emit, so the run must stop. **Exit 2.**

- **`emit-vex` produces a document.** A VEX emitted without waivers is *not wrong*. Every finding
  carries CycloneDX `in_triage` / OpenVEX `under_investigation`, which states exactly what is
  true: these were not analysed. The document is honest about its own limits, so refusing to
  write it would withhold accurate information rather than prevent inaccurate information.
  **Warn on stderr, exit 0.**

The rule, stated so it generalises to future commands:

> An unreadable `--waivers` path **fails** any command whose output asserts a verdict, and
> **warns** any command whose output can state its own incompleteness.

### What this ADR also decides

1. The asymmetry is **documented in `docs/cli-reference.md`**, not only in source docstrings.
2. It is **locked by a test** (`tests/cli/test_waivers_missing_path_contract.py`) that exercises
   all three commands against the same missing path in one place. Any future command taking
   `--waivers` must be added there with a deliberate choice of side.
3. `DEF-001` is closed as **not a defect**.

## Consequences

**Positive.** The contract becomes discoverable and testable rather than an accident of
implementation order. An adopter can learn one rule instead of three behaviours. No breaking
change, no migration, no version bump.

**Negative / accepted.** An operator who types `--waivers` wrongly in a CI job that only calls
`emit-vex` still gets exit 0, and the warning goes to stderr where CI logs may bury it. The
mitigation is that the emitted document is honest — a downstream consumer reading `in_triage`
sees "not analysed", not a false "not affected". This is a deliberate trade of loudness for
truthfulness, and it is the reason `--strict-waivers` was considered and rejected: a third
semantics for the same condition costs more than it buys.

**Revisit if** evidence appears that adopters are publishing `in_triage` VEX documents believing
their waivers applied. That is the failure this ADR accepts as residual, and it would be
grounds to reopen — not the inconsistency itself, which is now intended.

## Alternatives considered

- **Make `emit-vex` exit 2 (align on the gate side).** Rejected: it would reverse a one-day-old
  fix on the argument that consistency beats correctness, and would suppress a document that is
  accurate about its own gaps. Breaking, requiring v10.1.0 and a migration note, for no gain in
  the truthfulness of any artifact.
- **Make the gates warn instead of fail (align on the document side).** Rejected outright: an
  `evaluate` run that silently loses its waivers reports wrong verdicts, which is the exact class
  of silent-wrong defect the kit exists to prevent.
- **Add `--strict-waivers` to `emit-vex`.** Rejected: introduces a third behaviour for one
  condition and pushes the decision onto every adopter, when the correct default is knowable.
