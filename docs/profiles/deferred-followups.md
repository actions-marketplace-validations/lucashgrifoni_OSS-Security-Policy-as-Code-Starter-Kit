# Profile maturity - deferred follow-ups

Items intentionally deferred in earlier documentation rounds. Several items below are **targeted for the v4.0.0 major** on this branch; treat user-facing guarantees as tied to **`CHANGELOG.md`** and the eventual **`v4.0.0` tag**, not an implied PyPI publication date.

## CLI and listing

- *(Targeted for v4.0.0)* `profiles` flags `--only-extreme`, `--advisory-only`, `--family`, plus JSON `profile-list/v2` posture metadata.
- New mandatory fields on bundled `profile.yaml` beyond what the loader already tolerates.

## Reports and scoring

- *(Targeted for v4.0.0)* JSON report contract **`reports/0.3`** with `summary_by_gate_role` and `gate_execution_model` (see **`docs/reports-contract-v0.3.md`**).
- Score aggregation or merged role of gate beyond current `fail-on` mapping.

## Policy data

- New controls to represent live-only posture where the kit today documents an honest limit.
- Changing bundled `controls:` lists or turning `github-aws-level-2` / `github-azure-level-2` into hard-gates.

## Evidence

- Synthetic evidence that would require inventing unsupported JSON fields or declaring PASS without schema-backed content.

## Repository hygiene (resolved for the example fixture)

- The root `.gitignore` still ignores `.oss-policy-kit/` **globally**, except under **`examples/hardened-repo/.oss-policy-kit/`** via negated patterns scoped to **`evidence/`**. A nested **`examples/hardened-repo/.oss-policy-kit/.gitignore`** ignores everything in that directory except `.gitignore` itself and **`evidence/**`**, so only the synthetic JSON bundle is meant to be committed. Other paths named `.oss-policy-kit/` remain ignored.

Revisit the sections above only when the product owner accepts the corresponding scope expansion.
