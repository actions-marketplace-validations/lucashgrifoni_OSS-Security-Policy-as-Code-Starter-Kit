# Hardened example

Small repository layout that satisfies the `github-level-1` profile checks used in tests and demos.

This fixture represents the project's recommended adoption baseline and is expected to evaluate with `pass: 14` on `github-level-1`.

## What this fixture is good for

- Demonstrating starter-level posture (`github-level-1`) and general clone-visible hygiene.
- Exercising synthetic evidence flows under `.oss-policy-kit/evidence/` for single-platform extreme tracks.
- Regression testing for bundled examples (`hardened` vs `vulnerable`).

## What this fixture is **not** claiming

- It is not a live-platform proof pack for GitHub/Azure/AWS organizations.
- A run with `fail == 0` is not equivalent to all controls being `pass`.
- `self-attested`, `not-evaluated`, and operational warnings remain expected in some profiles.

## Known representativity limits

From the 2026-04-22 validation baseline, this fixture is not expected to be universally green across all advisory tracks. In particular:

- `github-level-2`
- `github-release-hardening-2`
- `github-aws-level-2`
- `github-azure-level-2`

can still fail on GitHub-centric signal controls (notably `GH-PROV-023` and/or `SEC-SECRETS-050`) depending on the exact fixture contents. That should be interpreted as a fixture-coverage limitation, not as automatic profile invalidation.
