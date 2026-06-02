# ADR-036 - Promote OSCAL and in-toto-bundle export to GA (`export-evidence`, v7.0.0)

- **Status**: accepted (targets v7.0.0, ADDITIVE / non-breaking) — 2026-06-01
- **Date**: 2026-06-01
- **Context window**: v7.x roadmap horizon — "Contract modernization & ecosystem interoperability"
- **Related**: ADR-012 (`export-evidence` registry, which named `oscal`/`in-toto-bundle`/`guac` as future formats), roadmap plan §3.1/§3.2/§6 (v7.x)

## Context

`export-evidence` (ADR-012) shipped with `chainloop` and `sarif` renderers and documented
`guac`, `oscal`, and `in-toto-bundle` as **future** formats that "plug in without changing the
CLI shape". The v7.x roadmap (§6, item 8) promotes `oscal` and `in-toto-bundle` from future to
**GA v0.1** because they feed the GRC/audit narrative (OSCAL) and the attestation narrative
(in-toto) that v8/v9 build on. `guac` stays deferred — its backlog stub gates promotion on
">1 adopter request" to avoid duplicating Chainloop's graph integration.

## Decision

Implement two renderers in the existing `export-evidence` registry and add them to
`_SUPPORTED_FORMATS`:

- **`oscal`** → an OSCAL **Assessment Results** JSON document (`assessment-results` model):
  the evaluated repo as the assessment subject, each control result as an OSCAL `finding` /
  `observation` with the kit as `assessment-assets`. Targets OSCAL 1.1.x JSON.
- **`in-toto-bundle`** → an in-toto **attestation** (statement) wrapping a custom predicate
  `https://oss-policy-kit/attestations/policy-evaluation/v0.1`, with `subject` = the evaluated
  repo (name + optional digest) and `predicate` = summary + per-control results. This is the
  **unsigned** statement; signing (cosign/Sigstore) is out of scope here and is the v8 ATTESTED
  track (the bundle is the input to that signing step).

Both get `--validate` structural checks (OSCAL: `assessment-results.metadata` + `results`;
in-toto: `_type` = `https://in-toto.io/Statement/v1`, `subject` array, `predicateType`,
`predicate`). `guac` is **not** added.

## Alternatives considered

1. **Promote `guac` too.** Rejected — its own stub defers it to real adopter demand (risk of
   duplicating Chainloop's GUAC integration); GA criterion not met.
2. **Sign the in-toto bundle now (keyless cosign).** Rejected for v7.0.0 — signing is the v8
   ATTESTED engine track (ADR-028 horizon); v7 produces the unsigned statement that signing
   later consumes. Bundling signing here would inflate v7.0.0 scope and the assurance model.
3. **OSCAL component-definition instead of assessment-results.** Rejected — the kit produces
   *assessment* output (pass/fail/observations), which maps to `assessment-results`, not a
   component capability catalog.

## Consequences

- The two registry slots that were stubs since v6.0.0 become real, exercising the "future
  formats plug in without CLI change" promise ADR-012 made.
- OSCAL feeds GRC/audit consumers; the in-toto statement is the unsigned precursor the v8
  attestation track signs — sequencing the roadmap cleanly.
- Trade-off: two more renderers + validations + golden fixtures; bounded by the report-projection
  shape already used by `chainloop`/`sarif`.

## References

- [OSCAL 1.1 assessment-results](https://pages.nist.gov/OSCAL/resources/concepts/layer/assessment/assessment-results/) · [in-toto attestation spec](https://github.com/in-toto/attestation)
- ADR-012 (`export-evidence` registry + future-format promise); roadmap plan §3.1/§3.2/§6
- `src/oss_policy_kit/cli/export_evidence.py`
