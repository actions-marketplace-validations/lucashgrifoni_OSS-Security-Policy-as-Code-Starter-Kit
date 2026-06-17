# ADR-040 - CISA Secure by Design Pledge readiness signals (CISA-SBD-*)

- **Status**: accepted
- **Date**: 2026-06-16
- **Context window**: v10 additive slice (loop-runner build)
- **Related**: ADR-016 (`ai-agent-baseline-1` pattern), CRA vulnerability-handling track; references RFC 9116, ISO/IEC 29147, ISO/IEC 30111

## Context

CISA's Secure by Design Pledge defines seven voluntary goals. Only a subset is observable in
a repository clone; the rest (security-patch uptake, intrusion-detection telemetry) require
customer/runtime data the kit cannot and should not collect. Adopters preparing for OSS
publication asked for a clone-visible "secure-by-design readiness" signal that does not
overclaim.

## Decision

Add three signal/evidence-grade `CISA-SBD-*` controls for the clone-observable subset, bundled
in `oss-publish-readiness-1`. These are **readiness signals, never "pledge fulfilled"**:

- `CISA-SBD-VDP-001` (pledge goal 6) — published VDP: RFC 9116 `.well-known/security.txt`
  with a `Contact:` field (strong), or a `SECURITY.md` disclosure section (weaker, prompts
  also publishing security.txt). Maps to ISO/IEC 29147.
- `CISA-SBD-CVE-003` (pledge goal 3) — published advisories carry CWE identifiers
  (advisories.json / CSAF). Maps to ISO/IEC 30111 hygiene.
- `CISA-SBD-SECRETS-005` (pledge goal 5) — default-credential / hardcoded-secret hygiene,
  **evidence-backed by composing the existing gitleaks SARIF** (`SAST-GITLEAKS-069`). It does
  NOT re-scan: PASS when the composed SARIF is clean, FAIL when it has findings,
  `MANUAL_REVIEW_REQUIRED` when the evidence is absent or unparseable.

The MFA goal (goal 4) maps to the existing `ORG-MFA-001` (evidence-backed); goals that are
runtime/telemetry are logged as out-of-scope in `docs/framework-alignment.md`.

## Alternatives considered

1. **Implement all seven pledge goals.** Rejected — patch uptake and intrusion detection are
   runtime/customer-telemetry, outside the clone-only architecture.
2. **Re-scan for secrets inside the control.** Rejected — the kit composes existing scanner
   evidence; it does not duplicate scanner engines (`CISA-SBD-SECRETS-005` reuses the gitleaks
   SARIF).
3. **Label these as compliance/conformance.** Rejected — they are readiness signals; the kit
   makes no certification or "pledge fulfilled" claim.

## Consequences

- OSS publishers get a clone-visible secure-by-design readiness check mapped to CISA SbD and
  ISO/IEC 29147/30111.
- Honest assurance: VDP/CWE are signals, secret hygiene is evidence-backed (composed), MFA is
  evidence-backed; out-of-scope goals are documented, not faked.
- Overlaps with the CRA vulnerability-handling track by design; the disclosure signals are
  shared, not duplicated.

## References

- CISA Secure by Design Pledge (seven goals)
- RFC 9116 (security.txt); ISO/IEC 29147 (vulnerability disclosure); ISO/IEC 30111 (handling)
