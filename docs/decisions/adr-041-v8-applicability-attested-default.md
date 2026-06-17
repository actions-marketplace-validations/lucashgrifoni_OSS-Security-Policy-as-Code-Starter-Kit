# ADR-041 — v8.0.0: applicability engine and ATTESTED become the default

- **Status:** accepted (v8.0.0)
- **Date:** 2026-06-19
- **Realizes:** ADR-028 PR5 (the deferred default flip)
- **Related:** ADR-028 (applicability engine + ATTESTED state, opt-in), ADR-027 (reports/2.0 default)

## Context

ADR-028 shipped, as opt-in (v7.1.0):

- an **applicability engine** that resolves a control whose declared precondition is unmet to
  `NOT_APPLICABLE` (consulted only behind `--applicability-engine`), and
- an **ATTESTED** control state, emitted (behind `--enable-attested`) when a control's pass is anchored
  on a verified attestation record (`PROV-VERIFY-061`: transparency-log inclusion + fresh `verified_at`).

The default flip was deferred so the kit's state vocabulary
(`PASS/FAIL/UNKNOWN/NOT_APPLICABLE/ATTESTED`) could align with OpenSSF Scorecard v6 / OSPS conformance.
At v8.0.0 the maintainer elects to lead this alignment rather than wait, with the opt-out flags below
preserving the prior behavior for one deprecation cycle.

Until v8.0.0 the engine covered only three container controls (`CONT-IMAGE-001/002/003`), whose
evaluators already degrade to `NOT_APPLICABLE` natively — so enabling the engine changed nothing
observable. v8.0.0 therefore also **expands applicability declarations** so the flip delivers real,
honest value.

## Decision

1. **Flip the CLI defaults.** `evaluate` and `evaluate-many` default to the applicability engine **on**
   and ATTESTED resolution **on**. Opt out for one deprecation cycle with `--no-applicability-engine`
   and `--no-enable-attested`. The lower-level programmatic `run_evaluation()` default is left **off**
   for backward compatibility — library callers opt in explicitly or go through the CLI.
2. **No PASS is migrated and no FAIL is relaxed.** `NOT_APPLICABLE` only replaces a status whose
   declared precondition is genuinely unmet; `ATTESTED` only replaces a `PASS` already anchored on a
   verified attestation. The fail-closed guarantees of ADR-028 are unchanged.
3. **Expand applicability to file-based control families** (additive; declared in `catalog.yaml` via
   `applicability.requires_any_files`, matching each scanner/parser's own file-detection globs):
   - Terraform `IAC-TF-001..012` → `**/*.tf`, `**/*.tf.json`
   - Bicep `IAC-BICEP-001..006` → `**/*.bicep`
   - GitLab CI `GL-PIPE-{001-008,010,012}` → `.gitlab-ci.yml`/`.yaml` (evidence-based 009/011 excluded)
   - Azure Pipelines `AZ-PIPE-027..030`, `AZ-{SEC,SCA,SBOM}` → `azure-pipelines.*` (evidence-based
     `AZ-PLAT/IDENT/SCONN/WIFEV/ART*` excluded)
   - AWS CodeBuild/CodePipeline `AWS-{CI-037,SECRET-038,SEC-039,SCA-040,SBOM-041,PROV-043,PIPE-042}` →
     `buildspec*`/`codepipeline.*` (evidence-based `CP-044/CB-045/*-056..059` excluded)
4. **No report-contract bump.** reports/2.0 already enumerates all five states (ADR-027), so the change
   is *default emission*, not output shape. reports/2.0 stays the default.

Evidence-based controls (`automation: not_observable_locally`) are deliberately **excluded** from the
file precondition: a missing CI file does not make a platform-configuration control non-applicable; it
remains gated on its evidence file.

## Consequences

- **Breaking for unpinned consumers** who branch on exact status strings: controls for technology a
  repo does not use now resolve to `NOT_APPLICABLE` by default (previously `UNKNOWN` for IaC, `FAIL` for
  the platform-CI "presence" controls), and verified-provenance passes surface as `ATTESTED`. Mitigated
  by `--no-applicability-engine` / `--no-enable-attested` (one cycle) and the migration guide.
- More honest scoring: a Python repo no longer carries 12 `UNKNOWN` Terraform controls; a GitHub-only
  repo no longer "fails" GitLab/Azure/AWS pipeline-presence controls.
- Verified with `scripts/v8-applicability-impact.py`: presence/IaC controls flip `FAIL/MRR → NA` when
  the technology is absent, with **zero false-`NA`** on a repo where the files are present
  (`examples/hardened-repo`).

## Alternatives considered

- **Keep opt-in indefinitely** — rejected: diverges from Scorecard v6 once it GAs and leaves the engine
  unused by default.
- **Bump the report contract to 3.0** — rejected: reports/2.0 already carries the states; the change is
  default emission, not shape.
- **Flip the library `run_evaluation()` default too** — deferred: keeping it off preserves backward
  compatibility for programmatic callers; revisit if the CLI/library split proves confusing.
