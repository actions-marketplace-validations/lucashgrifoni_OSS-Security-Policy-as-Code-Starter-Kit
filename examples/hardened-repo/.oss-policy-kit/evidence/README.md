# Evidence JSON (synthetic fixture)

These files back **evidence-backed** controls in the bundled `examples/hardened-repo` fixture. They
are **maintainer-supplied** (self-attested) JSON and are not live API exports. In particular they do
**not** carry a `collection` block (`evidence_collection_method: "live"`) nor a `posture_support`
block, so evaluators treat them as the synthetic baseline — usually yielding `self-attested`
(not `pass`) for strict evaluators that require API-attested posture.

Synthetic identifiers follow kit guidance (`example-org` / `example-repo`, `main`, `000000000000`).

## Fixture scope per file

| File | Purpose in fixture | Why it is safe to keep self-attested |
| --- | --- | --- |
| `branch-protection.json` | GitHub branch protection baseline | Replaced by `collect-evidence --platform github` for live posture |
| `github-rulesets.json` | GitHub rulesets posture | Replaced by `collect-evidence --platform github` |
| `github-environment-protection.json` | Required reviewers on `production` | Replaced by `collect-evidence --platform github` |
| `github-secret-scanning.json` | Secret scanning / push protection | Replaced by `collect-evidence --platform github` |
| `azure-branch-policies.json` | Azure Repos branch policies (min reviewers, build validation, reset votes, block last pusher, bypass restricted) | Replaced by `collect-evidence --platform azure`; live form adds `posture_support.policies_api_reachable` |
| `azure-pipeline-governance.json` | Environment approvals + federated service connections | Replaced by `collect-evidence --platform azure`; live form adds `posture_support` with four API reachability flags |
| `azure-sbom-artifact.json` / `azure-provenance-artifact.json` | Artifact-bound SBOM / provenance posture | Kept self-attested; live digests must come from the release pipeline (not emitted by REST APIs) |
| `aws-codebuild-project.json` | CodeBuild posture (no privileged mode, no plaintext creds, role configured) | Replaced by `collect-evidence --platform aws` when `AWS_CODEBUILD_PROJECT` is set |
| `aws-codepipeline.json` | CodePipeline posture (manual approval, encrypted artifact store, non-parallel execution) | Replaced by `collect-evidence --platform aws` when `AWS_CODEPIPELINE_NAME` is set |
| `aws-sbom-artifact.json` / `aws-provenance-artifact.json` | Artifact-bound SBOM / provenance posture | Kept self-attested; digests come from the release pipeline |
| `org-mfa-posture.json` | Organization MFA enforcement attestation | Kept self-attested; the kit does not collect org-wide MFA automatically |

## Expected status in `examples/hardened-repo`

- Daily profiles (`*-level-1`, `*-level-2`, `*-release-hardening-1`, `*-release-hardening-2`) rely on
  a mix of repository signals and self-attested JSON. Expect a PASS-dominant report with a few rows
  marked `self-attested` for the artifact SBOM / provenance slots.
- Extreme hard-gate profiles (`*-level-3`, `*-release-hardening-3`) require API-attested posture for
  the strictest controls. On this fixture those rows still resolve to `self-attested`, which is the
  correct answer for synthetic inputs. `fail == 0` is achievable, but it **does not** prove live
  platform posture — replace the files with `collect-evidence` output to move those rows to `pass`.

## Re-running

```bash
python -m oss_policy_kit evaluate \
  --target . \
  --profile github-level-3 \
  --output-dir ./out/evidence-check
```

## Safe editing

`scaffold-evidence` never overwrites existing files unless `--force` is passed. If you edit these
JSONs, keep `attested_by: example-maintainer` (or similar non-live sentinel) to document that the
data is synthetic; use `collect-evidence` to replace them with live attestations.
