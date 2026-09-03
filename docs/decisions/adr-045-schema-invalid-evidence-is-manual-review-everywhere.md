# ADR-045 — Evidence that fails schema validation is `manual-review-required` on every platform

- **Status**: accepted — ratified 2026-08-12
- **Date**: 2026-08-12
- **Related**: ADR-044 (unreadable waivers: gate fails, document warns), the v10.0.12 fix `ef364c9` that stopped `SAST-SEMGREP-064` reading an uncountable tally as a clean scan

## Context

Several controls read a JSON evidence file and validate it against a packaged schema. When that
validation fails — a required field missing, a wrong type, a payload from a different tool — the
kit answered two different ways depending on the platform:

| Platform | Verdict | Effect on a gate |
|---|---|---|
| GitHub (`GH-PLAT-024/025/026`, `GH-IMMUTREL-070`, `ORG-ACTPOL-071`, `PLAT-BRPROT-015`) | `fail` | blocks |
| Azure (`AZ-PLAT-034/035`, `AZ-SCONN-056`, `AZ-WIFEV-057`, `AZ-ARTSBOM-058`, `AZ-ARTPRV-059`) | `manual-review-required` | asks a human |
| AWS (`AWS-CP-044`, `AWS-CB-045`, `AWS-CBIDENT-057`, `AWS-SBOMART-058`, `AWS-PROVART-059`) | `manual-review-required` | asks a human |

Same cause, same kind of file, two outcomes, and nothing recorded why.

The split was **not deliberate** — confirmed by the maintainer on 2026-08-12, and visible in the
code before that. `ORG-MFA-001` is a GitHub control that already answered
`manual-review-required`, so the divergence was not even consistent within the GitHub family.
More telling, `_parse_branch_protection_evidence` disagreed with *itself*: unreadable JSON and a
non-object root both returned `manual-review-required`, and a schema violation three branches
later returned `fail`. Three descriptions of the same situation — this reader cannot use this
file — and one of them answered differently.

The behaviour was pinned in `test_malformed_evidence_never_earns_credit.py` rather than changed
on sight, because changing it moves other people's gates and the direction was a contract
decision, not a bug fix.

## Decision

**A control that cannot read its evidence answers `manual-review-required`, on every platform.**

The reasoning is what each verdict actually claims:

- **`fail` is a statement about the repository.** It says: this control is not satisfied.
- **`manual-review-required` is a statement about the evidence.** It says: I do not know.

A schema violation is unambiguously the second. The kit did not discover that branch protection
is weak; it discovered that it cannot read the file that would describe branch protection.
Reporting `fail` has the gate assert something it never established.

That distinction is the product's own argument. The kit exists to refuse to turn *unknown* into
*clean* — the rule it applies to an unreadable SARIF, to a scaffolded template, to a scan that
timed out. `v10.0.12` shipped a fix for the exact violation of it in the other direction:
`SAST-SEMGREP-064` was reading an uncountable tally as `pass` at high confidence. Turning
unknown into `fail` is the same error mirrored: less dangerous, because it over-reports rather
than under-reports, but still the tool speaking past its evidence.

**The operational concern is real and is answered by policy, not by the verdict.** Broken
evidence that only produces a yellow result tends to stay broken. But the fix for that is to let
the operator decide, and `--fail-on degraded` already does exactly this: it exits 1 on `fail`
**or** `manual-review-required`. A release candidate can demand that unreadable evidence blocks;
a feature branch need not. That belongs to gate policy, which the operator sets per context, and
not to the control, which has one honest answer.

## Consequences

- Six branches change verdict: five `if error:` returns in `evaluators/github.py` and the
  `ValidationError` handler in `_shared._parse_branch_protection_evidence`. All six already used
  `confidence="low"` and a reason naming the schema; only the status moves.
- **No pipeline that passed starts failing.** The change only ever turns a red control yellow.
  Users whose GitHub evidence is malformed will see `manual-review-required` where they saw
  `fail`; users on `--fail-on degraded` keep the same exit code.
- Consumers reading `state` in `reports/2.0` will see `UNKNOWN` for these controls where they
  previously saw `FAIL` (`UNKNOWN` is the wire projection of `manual-review-required`; the
  Markdown report prints the domain string). `summary_by_status` moves the same count from `FAIL`
  to `UNKNOWN`. The contract shape is unchanged — no new key, no new `state` value — but the
  value in these six cases is not. This is why it ships as its own change with this ADR attached,
  rather than folded into an unrelated release.
- `test_malformed_evidence_never_earns_credit.py` now documents the rule instead of the
  observation. Its table still names the status per control rather than asserting one constant,
  so a future divergence surfaces as a diff on the row that moved.

## Alternatives considered

**Standardise on `fail` everywhere.** Rejected. It is the direction that breaks existing users —
Azure and AWS adopters with imperfect evidence would find pipelines newly red on a patch release
— and it entrenches the confusion between "unsatisfied" and "unknown" that the rest of the
product works to keep apart.

**Document the asymmetry as deliberate.** This was a genuine candidate, and it would have been
the right answer under one hypothesis: that GitHub evidence is API-collected by
`collect-evidence` while the other platforms' is largely hand-declared, making a malformed
GitHub file a sign of a broken collector rather than a careless operator. Nothing in the history
supports that reading, and the maintainer confirmed the split was accidental. Keeping an
unexplained difference in a compliance tool also costs something every time it is audited.

**Add a distinct status for "evidence unreadable".** Rejected as disproportionate. It would be a
`reports/2.0` contract change — a new `state` value every downstream consumer must learn — to
express something `manual-review-required` plus a reason naming the schema already conveys.
