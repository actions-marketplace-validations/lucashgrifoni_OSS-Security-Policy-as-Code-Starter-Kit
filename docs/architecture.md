# Architecture

This document describes the runtime structure of the OSS Security Policy as Code Starter Kit and the trust boundaries behind its results.

## Design goals

- keep the implementation small and testable
- separate product meaning from low-level file parsing
- stay honest about what can and cannot be proven from a local clone
- prefer explicit degradation over optimistic false passes

## Package layout

### Domain (`oss_policy_kit.domain`)

Core datatypes and enums:

- `ControlStatus`
- `ControlResult`
- `ExecutionReport`
- `WaiverRecord`
- `EvidenceCollectionMethod`, `LiveCollectionMetadata`, `EvalOutcome`
- plugin typing: `domain/plugin_contract.py` (`EvaluatorPlugin` protocol)

Third-party evaluators register under the **`oss_policy_kit.evaluators`** entry-point group; the application layer merges them into **`EVALUATOR_REGISTRY`** after built-ins load (no overrides).

### Application (`oss_policy_kit.application`)

Product orchestration and control semantics:

- catalog and profile loading
- waiver parsing and validation
- per-control evaluators (from **v3.1.0**, many paths downgrade or gate **confidence** when only YAML keywords or unfilled evidence digests are present, so **`signal`** vs **`evidence-backed`** in the catalog matches runtime honesty more closely)
- report assembly and status summarization
- JSON and Markdown report emission

### Adapters (`oss_policy_kit.adapters`)

Boundary adapters:

- local path resolution
- optional OpenSSF Scorecard JSON ingestion

### Infrastructure (`oss_policy_kit.infrastructure`)

Low-level mechanics:

- safe YAML loading
- static GitHub Actions workflow parsing
- static Azure Pipelines workflow parsing
- static AWS CodeBuild buildspec and committed CodePipeline file discovery
- optional REST evidence collectors under **`oss_policy_kit.infrastructure.collectors`** (for example GitHub via **`httpx`**)

### CLI (`oss_policy_kit.cli`)

Typer-based command surface with:

- explicit `evaluate` subcommand
- bundled profile discovery via `profiles` and `--show-profiles`
- compatible top-level invocation without `evaluate`
- machine-friendly summary output
- CI-friendly exit codes

## Bundled policy data

Runtime policy assets are packaged from:

- `src/oss_policy_kit/data/controls/catalog.yaml`
- `src/oss_policy_kit/data/profiles/*/profile.yaml`
- `src/oss_policy_kit/data/schema/evidence-branch-protection.schema.json`
- `src/oss_policy_kit/data/schema/evidence-github-rulesets.schema.json`
- `src/oss_policy_kit/data/schema/evidence-github-environment-protection.schema.json`
- `src/oss_policy_kit/data/schema/evidence-github-secret-scanning.schema.json`
- `src/oss_policy_kit/data/schema/evidence-azure-branch-policies.schema.json`
- `src/oss_policy_kit/data/schema/evidence-azure-pipeline-governance.schema.json`
- `src/oss_policy_kit/data/schema/evidence-aws-codebuild-project.schema.json`
- `src/oss_policy_kit/data/schema/evidence-aws-codepipeline.schema.json`
- `src/oss_policy_kit/data/schema/evidence-aws-codecommit-review-posture.schema.json`

The public report schema remains under:

- `reports/schema/evaluation-result.schema.json`
- `reports/schema/evidence-branch-protection.schema.json`
- `reports/schema/evidence-github-rulesets.schema.json`
- `reports/schema/evidence-github-environment-protection.schema.json`
- `reports/schema/evidence-github-secret-scanning.schema.json`
- `reports/schema/evidence-azure-branch-policies.schema.json`
- `reports/schema/evidence-azure-pipeline-governance.schema.json`
- `reports/schema/evidence-aws-codebuild-project.schema.json`
- `reports/schema/evidence-aws-codepipeline.schema.json`
- `reports/schema/evidence-aws-codecommit-review-posture.schema.json`

## Evidence and trust model

The kit evaluates a **local repository clone**. Not all controls are equally observable from local files.

### Evidence tiers

| Tier | Meaning | Typical confidence |
| --- | --- | --- |
| Local automated | Derived entirely from files in the clone | `high` or `medium` |
| Local partially observable | Visible locally, but not equivalent to live platform truth | `medium` or `low` |
| Self-attested | Maintainer-supplied evidence file with schema validation only | `low` |
| Manual review required | Not safely provable from local files | limitation is known with high confidence |
| Not observable | Structurally outside the clone | limitation is known with high confidence |

### Structured evidence

Consumer repositories may optionally include evidence files under:

- `.oss-policy-kit/evidence/`

These files are local inputs to the evaluator. Repositories may version them deliberately, but many teams will keep them untracked and generate them only for local validation or release review.

Current structured evidence supported by the kit:

| Control | Evidence file | Schema |
| --- | --- | --- |
| `PLAT-BRPROT-015` | `.oss-policy-kit/evidence/branch-protection.json` | `reports/schema/evidence-branch-protection.schema.json` |
| `GH-PLAT-024` | `.oss-policy-kit/evidence/github-rulesets.json` | `reports/schema/evidence-github-rulesets.schema.json` |
| `GH-PLAT-025` | `.oss-policy-kit/evidence/github-environment-protection.json` | `reports/schema/evidence-github-environment-protection.schema.json` |
| `GH-PLAT-026` | `.oss-policy-kit/evidence/github-secret-scanning.json` | `reports/schema/evidence-github-secret-scanning.schema.json` |
| `AZ-PLAT-034` | `.oss-policy-kit/evidence/azure-branch-policies.json` | `reports/schema/evidence-azure-branch-policies.schema.json` |
| `AZ-PLAT-035` | `.oss-policy-kit/evidence/azure-pipeline-governance.json` | `reports/schema/evidence-azure-pipeline-governance.schema.json` |
| `AWS-CP-044` | `.oss-policy-kit/evidence/aws-codepipeline.json` | `reports/schema/evidence-aws-codepipeline.schema.json` |
| `AWS-CB-045` | `.oss-policy-kit/evidence/aws-codebuild-project.json` | `reports/schema/evidence-aws-codebuild-project.schema.json` |
| `AWS-CC-046` | `.oss-policy-kit/evidence/aws-codecommit-review-posture.json` | `reports/schema/evidence-aws-codecommit-review-posture.schema.json` |
| `AWS-SBOMART-058` | `.oss-policy-kit/evidence/aws-sbom-artifact.json` | `reports/schema/evidence-aws-sbom-artifact.schema.json` |
| `AWS-PROVART-059` | `.oss-policy-kit/evidence/aws-provenance-artifact.json` | `reports/schema/evidence-aws-provenance-artifact.schema.json` |

### Branch protection evidence

For `PLAT-BRPROT-015`, the kit validates file structure and required flags, but it does **not** call the GitHub API.

Implications:

- broken or unreadable evidence degrades to `manual-review-required`
- missing required protections do not pass silently
- self-attested evidence remains lower-trust than live GitHub confirmation
- `github-release-hardening-1` can legitimately end with `pass` plus `manual-review-required` or `self-attested`

## CLI trust boundaries

- paths are resolved and validated before evaluation
- YAML parsing uses safe loading only
- the tool does not execute repository code
- report output reflects local evidence, optional supplemental inputs, and explicit evaluator limitations

## Known limitations

The kit cannot reliably prove:

- live GitHub branch protection or rulesets
- organization-level settings outside the clone
- runtime behavior of reusable workflows, composite actions, or complex expressions
- certification or compliance against a formal framework
- live AWS CodeBuild project settings or full CodePipeline definitions unless exported or evidenced locally

Workflow analysis is static. That is a deliberate tradeoff, not an implementation accident.
