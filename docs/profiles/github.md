# GitHub profiles

Pure GitHub family in this kit: **seven** ids (`github-level-1..3`, `github-release-hardening-1..3`, plus the legacy alias `github-release-hardening`).

## Usage classes

- **Daily baseline**: `github-level-1`, `github-level-2`, `github-release-hardening-1`, `github-release-hardening-2`.
- **Extreme hard-gate**: `github-level-3`, `github-release-hardening-3`.
- **Legacy compatibility**: `github-release-hardening` only (same control set as `github-release-hardening-1`).

## What each ladder means

- **level-1**: clone-visible baseline (governance files + workflow hygiene).
- **level-2**: stricter GitHub workflow posture (still signal-heavy in some areas).
- **level-3**: hard-gate with GitHub platform evidence (`rulesets`, environments, secret scanning), org MFA posture evidence, SBOM quality, and evidence freshness.

## Release ladder

- **release-hardening-1**: level-1 plus branch-protection/evidence discipline.
- **release-hardening-2**: level-2 style strictness with release-oriented evidence expectations.
- **release-hardening-3**: strictest GitHub release posture in this kit (extreme reference profile).

## Practical maturity and fixture limits

GitHub is the most mature path in this kit (collector support, schema coverage, and profile ergonomics).  
Still, the hardened fixture is **not** expected to be universally green across all GitHub profiles:

- 2026-04-22 validation recorded fixture failures on `github-level-2` and `github-release-hardening-2` (`GH-PROV-023` / `SEC-SECRETS-050`).
- That reflects fixture representativity limits, not an automatic defect in those profiles.

## Legacy alias handling

`github-release-hardening` remains supported for backward compatibility and resolves to the same controls as `github-release-hardening-1`. The CLI:

- emits a warning on `evaluate --profile github-release-hardening`
- marks it in `profiles --format json` with `is_legacy_alias: true` and canonical id mapping

For new docs and automation, use `github-release-hardening-1`.

## See also

- [How `recommend-profile` reads `.oss-policy-kit/evidence/`](overview.md#how-recommend-profile-reads-oss-policy-kitevidence) — why a synthetic evidence pack alone can produce a `*-release-hardening-2` suggestion, and how to read it honestly.
