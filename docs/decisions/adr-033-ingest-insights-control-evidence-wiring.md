# ADR-033 - Wire ingested Security Insights into controls as self-attested evidence (v7.0.0)

- **Status**: accepted (targets v7.0.0, ADDITIVE to evaluation; ships inside the v7.0.0 bundle) — 2026-06-01
- **Date**: 2026-06-01
- **Context window**: v7.x roadmap horizon — "Contract modernization & ecosystem interoperability"; completes the fenced follow-up of ADR-032
- **Related**: ADR-032 (`ingest-insights` read/validate/report), ADR-011 (`emit-insights`), ADR-027 (reports/2.0 flip — same v7.0.0 bundle), `docs/insights-ingestion.md`, backlog item `ingest-security-insights`

## Context

ADR-032 (v6.7.0) added `ingest-insights`: it discovers, parses, structurally validates,
and reports a target's `SECURITY-INSIGHTS.yml` as an explicitly **self-reported** posture
summary. ADR-032 deliberately **fenced off** the harder half of the original backlog
acceptance bar ("≥3 controls accept Insights as evidence") because wiring self-reported
fields into the evaluation engine touches the 212-evaluator core and the golden reports, and
needed an honest per-control mapping decision that did not exist yet.

This ADR makes that decision. It is the remaining increment of the `ingest-security-insights`
backlog item, sequenced **after** the reports/2.0 flip (ADR-027) inside the v7.0.0 bundle so
the golden reports are regenerated once on the flipped `2.0` baseline rather than twice.

### The honesty problem this ADR must pin down (carried from ADR-032)

A `SECURITY-INSIGHTS.yml` is **self-asserted by the project author**. It is not independent
evidence: a project can declare `accepts-vulnerability-reports: true` without that being
verifiable from the clone. The kit's core guard-rail is assurance honesty — never inflate a
deterministic or evidence-backed gate with a weak, self-reported signal
(`controlled-evolution` §5.3; README non-goals). So the decision is **which controls may
consume Insights, at what assurance grade, and with what provenance label** — and, just as
important, which controls must **not** consume it.

## Decision

In **v7.0.0**, when a valid `SECURITY-INSIGHTS.yml` is present under the target, the engine
makes its recognized fields available to a **small, explicit allowlist of signal-grade
governance/disclosure controls** as a `self-attested` evidence contribution. The contribution
can only **raise** a control that would otherwise be `UNKNOWN`/`manual-review-required` to a
`PASS` carrying the existing `ControlStatus.SELF_ATTESTED` state (reports/2.0: `PASS` with
provenance metadata `self-reported`). It can **never** override a deterministic `FAIL`, and it
is **never** consumed by deterministic or attestation-grade controls.

### The allowlist (exactly three controls, all `signal`/`evidence-backed` governance)

| Control | Current assurance | Insights field consumed | Effect |
|---|---|---|---|
| `GOV-DISC-013` — Responsible disclosure channel documented | `signal` | `accepts-vulnerability-reports` + `security-policy-url` (or `vulnerability-reporting.*`) | If absent-from-clone → `SELF_ATTESTED` PASS (provenance `self-reported`) instead of `manual-review-required` |
| `CRA-ART14-COORD-002` — Coordinated vulnerability disclosure policy (CRA Art. 14) | `signal` | `vulnerability-reporting.accepts-vulnerability-reports` + reporting contact/URL | Same: `SELF_ATTESTED` PASS when the clone has no deterministic proof |
| `GOV-DISC-065` — Disclosure channel SLA documented (CRA reporting readiness) | `evidence-backed` | `vulnerability-reporting.*` SLA/contact fields | Accepts the Insights file as **one** self-attested evidence source alongside the existing structured-evidence path; provenance always `self-reported` |

Three controls satisfies the original "≥3" bar without spreading self-report across the
catalog. All three are disclosure/reporting governance controls whose real-world source of
truth often *is* the project's self-declared `SECURITY-INSIGHTS.yml`.

### What the wiring MUST NOT do (assurance fence, retained)

- **No deterministic control consumes Insights.** `GOV-SEC-001` (SECURITY.md present) stays a
  pure file-presence check; a self-report cannot manufacture a file.
- **No `FAIL`→`PASS` laundering.** Insights can only lift `UNKNOWN`/`manual-review-required`
  (no clone-visible signal) to `SELF_ATTESTED`. A deterministic negative is never overridden.
- **Provenance is always explicit.** Every Insights-derived verdict carries
  `provenance: self-reported` in the per-control metadata and a one-line caveat in human
  output; reports/2.0 surfaces it as `SELF_ATTESTED`, distinct from `PASS evidence-backed` and
  from `ATTESTED` (signed).
- **Opt-in for one cycle.** The wiring is gated behind `--use-insights-evidence` (default off)
  in v7.0.0 so existing `evaluate` output is unchanged unless the operator asks for it; the
  default can flip in a later minor once adopters confirm the provenance labelling reads
  correctly. This keeps v7.0.0's *evaluation* behavior additive even though the release as a
  whole is breaking (the break is the reports/2.0 flip, ADR-027).
- **No fetch, no mutation.** Clone-local file only (same posture as ADR-032).

### Acceptance criteria

- The three allowlisted controls accept Insights fields as `self-attested` evidence behind
  `--use-insights-evidence`; `cli-api-ui-contract-validator` confirms no existing default
  output changed when the flag is off.
- A self-report cannot lift a deterministic `FAIL`; a regression test pins this.
- Golden reports for a fixture carrying a `SECURITY-INSIGHTS.yml` show `SELF_ATTESTED` with
  `provenance: self-reported` only under the flag.
- `docs/insights-ingestion.md` gains a "using Insights as control evidence" section with the
  honesty caveat.

## Alternatives considered

1. **Consume Insights for many controls (broad mapping).** Rejected — spreads self-report
   across the catalog and erodes assurance honesty. Three disclosure controls is the honest,
   defensible scope.
2. **Let Insights override `FAIL`.** Rejected outright — turns a self-declaration into a gate
   bypass; this is the exact failure mode the guard-rail forbids.
3. **On by default in v7.0.0.** Rejected — even additive, changing `evaluate` verdicts in the
   same release as the reports/2.0 flip compounds blast radius; ship behind a flag, flip later.
4. **A new status instead of reusing `SELF_ATTESTED`.** Rejected — `ControlStatus.SELF_ATTESTED`
   already exists and already maps cleanly into reports/2.0; inventing another state is churn.

## Consequences

- Closes the `ingest-security-insights` backlog item fully: the kit emits, ingests, validates,
  reports, **and** (opt-in) consumes Security Insights as honest self-attested evidence.
- The emit↔ingest↔consume loop is complete while assurance honesty is preserved by construction
  (allowlist + flag + provenance label + no-FAIL-override).
- Trade-off: one more flag and one more provenance path in the engine; mitigated by reusing the
  existing `SELF_ATTESTED` state and the ADR-032 loader/validator.

## References

- ADR-032 (`ingest-insights`) — the fenced predecessor this completes
- ADR-027 (reports/2.0 flip) — same v7.0.0 bundle; sequenced before this wiring
- [OpenSSF Security Insights spec](https://security-insights.openssf.org/)
- Controls: `GOV-DISC-013`, `CRA-ART14-COORD-002`, `GOV-DISC-065` in `src/oss_policy_kit/data/controls/catalog.yaml`
- `docs/insights-ingestion.md`; backlog `ingest-security-insights`
