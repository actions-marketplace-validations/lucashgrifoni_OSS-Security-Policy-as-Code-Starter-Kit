# ADR-038 - GitHub immutable-release + org-level Actions-policy evidence signals (v7.3.0)

- **Status**: accepted (v7.3.0)
- **Date**: 2026-06-09
- **Related**: ADR-007 (provenance-artifact evidence), ADR-028 (ATTESTED state), `docs/collector-parity.md`,
  release-hardening profiles

## Context

GitHub shipped two posture features the release-hardening track should be able to express:

- **Immutable releases** (GA 2025-10): release assets/tags are locked and a **release attestation**
  (tag + commit SHA + assets) is auto-generated.
- **Organization Actions policy** (2025-08): orgs can **block** third-party actions and **require
  SHA-pinning**.

Both are real posture signals, but **neither is visible from a clone** — immutable-release state and
org policy live in GitHub settings, not in the repository tree. The kit's existing release-hardening
controls already use the evidence-backed pattern (`GH-PLAT-024` rulesets, `GH-PLAT-025` environments):
a maintainer-supplied or API-collected JSON file records the posture.

## Decision

Add two **evidence-backed** controls (additive; new optional controls are backward-compatible per
`docs/policy-data-lifecycle.md`):

- **`GH-IMMUTREL-070`** — *Immutable releases enabled / release attestation evidenced*. Reads
  `.oss-policy-kit/evidence/github-release-immutability.json`
  (`evidence-github-release-immutability.schema.json`). PASS when `immutable_releases_enabled` and/or
  `release_attestation_present` is true; FAIL when present-but-off; **manual review (NOT_EVALUATED)**
  when the file is absent (never a false fail); FAIL on a malformed/unfilled file.
- **`ORG-ACTPOL-071`** — *Org-level Actions policy (block + SHA-pinning) evidenced*. Reads
  `.oss-policy-kit/evidence/github-actions-policy.json` (`evidence-github-actions-policy.schema.json`).
  PASS requires a restricted allowlist (`local_only`/`selected`) **and** `sha_pinning_required: true`.

Both are bundled into `github-release-hardening-2` and `github-release-hardening-3`, get
`scaffold-evidence --platform github` templates, and are evidence-file-driven.

**Compose, do not recreate.** The kit records the *presence* of GitHub's release attestation; it does
not re-verify the attestation cryptographically. The honest framing: this is posture evidence, not a
verification verdict.

## Alternatives considered

1. **Treat as clone `signal` from workflow text.** Rejected — org/release-settings posture is not in the
   clone; calling it a clone signal would be dishonest. Evidence-backed is the correct assurance.
2. **A new release-hardening profile for these.** Rejected — profile sprawl; the existing
   release-hardening-2/3 profiles are the natural, evidence-driven home.
3. **Auto-collect via API now.** Deferred — org Actions policy needs an org-admin token; release
   attestation via API is a follow-up. Evidence-file-driven first, exactly as `GH-PROV-023` shipped
   before `PROV-VERIFY-061`.
4. **Resolve the release attestation to `ATTESTED` (ADR-028).** **Implemented** (opt-in,
   fail-closed): when `--enable-attested` is set and `github-release-immutability.json` carries a
   `verification` block with transparency-log inclusion and a fresh `verified_at`, `GH-IMMUTREL-070`
   resolves to `ATTESTED` instead of `PASS` (mirrors `PROV-VERIFY-061`). Any verification gap keeps the
   historical `PASS` — never a false `ATTESTED`. The crypto verification runs in CI; the kit validates
   the record. `ORG-ACTPOL-071` stays PASS/FAIL (org config posture is not an attestable artifact).

## Consequences

- Release-hardening adopters can record and gate on immutable-release and org Actions-policy posture
  with honest assurance; absent evidence is manual review, not a fail.
- Additive: no existing control's pass/fail changes; new MRR rows appear in release-hardening-2/3 when
  evidence is unsupplied (the established baseline of those evidence-driven profiles).
- Follow-ups (out of scope here): collector API auto-gather; `ATTESTED` for the verified release
  attestation; org-policy allowlist pattern checks.

## References

- GitHub immutable releases (GA) — <https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/>
- GitHub Actions policy (block + SHA-pin) — <https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/>
- ADR-007, ADR-028; `docs/policy-data-lifecycle.md`
