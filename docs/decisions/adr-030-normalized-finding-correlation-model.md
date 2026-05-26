# ADR-030 - Normalized finding model with cross-scanner correlation (v10.0.0)

- **Status**: proposed (targets v10.0.0, BREAKING) — pending maintainer ratification (roadmap plan §11.5, §11.6)
- **Date**: 2026-05-25
- **Context window**: v10.x roadmap horizon — "AI/agentic depth & correlation maturity"
- **Related**: ADR-021 (EPSS/KEV prioritization), ADR-001 (SCA scanner choice), ADR-012 (export-evidence), `ROADMAP.md`

## Context

The kit composes scanner evidence (zizmor, OSV-Scanner, Gitleaks, Scorecard, Semgrep)
via SARIF/JSON adapters. Today that composition is shallow: there is per-adapter
normalization (e.g. `scorecard_json` normalized entries) and path-level dedup, but **no
cross-scanner finding model** — the same issue reported by two tools is not correlated,
and prioritization (EPSS/KEV, ADR-021) is applied in spots rather than as a first-class
layer over a unified finding set.

The market signal (ASPM-as-control-plane: normalize → dedup → prioritize → govern) is
exactly this capability, and Gartner projects 80% adoption in regulated verticals by
2027. The kit can deliver the honest, local-first slice of it: one normalized finding
view per run. But this is also the highest scope-creep risk in the roadmap — it must
**not** drift into an ASPM platform (persistent database, runtime, stateful triage).

Introducing a normalized finding shape changes the findings section of the report JSON,
which is breaking for consumers that parse it — hence a major bump.

## Decision

In **v10.0.0**, introduce a **normalized finding model** scoped to a single clone-only
run:

1. **Normalize** findings from all composed scanners into one internal schema
   (id, source tool, rule, location, severity, component, links).
2. **Deduplicate / correlate** across scanners by a deterministic key
   (component + rule/CWE + location), so the same issue from two tools collapses to one
   correlated finding that records all reporting sources.
3. **Prioritize** as a first-class layer: EPSS/KEV (ADR-021) and reachability signals
   (when a scanner exposes them, e.g. OSV-Scanner) attach to the normalized finding and
   drive an ordered, reproducible ranking.
4. **Hard scope fence (anti-ASPM).** Everything happens within one run: **no persistent
   database, no state carried between runs, no runtime/agent, no hosted triage.** This
   fence is part of the decision, not just a note, and is restated as a README non-goal.

The breaking finding-shape change ships with a migration note and updated golden
fixtures; `cli-api-ui-contract-validator` gates the contract change.

## Alternatives considered

1. **Keep per-adapter findings, no correlation.** Rejected — duplicate findings across
   tools mislead gate decisions and waste reviewer time; prioritization stays scattered.
2. **Build a stateful triage store / ASPM platform.** Rejected — violates the
   clone-only, no-runtime, no-database architecture; that ground belongs to dedicated
   ASPM tools the kit composes *with*, not competes against.
3. **Correlate but don't change the report shape.** Rejected — correlation that is not
   visible in the output delivers little; the shape change is the deliverable.
4. **Defer to a v9.x minor.** Rejected — the finding-shape change is breaking for
   consumers parsing the findings section; semver requires a major.

## Consequences

- One normalized, deduplicated, prioritized finding view per run — the honest local-first
  slice of the ASPM "control plane" pattern.
- EPSS/KEV/reachability prioritization becomes a coherent layer instead of spot logic.
- The findings section of the report changes shape (breaking); documented with a
  migration note and updated fixtures.
- The anti-ASPM fence is explicit and testable, protecting the project from the
  roadmap's biggest scope-creep risk.
- Trade-off: correlation keys must be tuned to avoid over-merging distinct issues;
  starts conservative (under-merge over over-merge) and tightens with fixtures.

## References

- ASPM trend (Gartner) — <https://www.gartner.com/reviews/market/application-security-posture-management-aspm-tools>, <https://apiiro.com/blog/gartner-on-aspm-what-it-means-for-your-security-strategy/>
- ADR-021 (EPSS/KEV), ADR-001, ADR-012
- `ROADMAP.md` (v10.x horizon); roadmap plan §6, §11.5–11.6
