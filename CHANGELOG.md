# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from **v1.0.0** onward. Releases prior to `1.0.0` used `0.x` with explicit notes when behavior or schema changed.

## [Unreleased]

- Removed maintainer-private planning notes from the public repository tree and excluded that local notes directory from future commits.
- Updated release evidence references so public docs describe the external validation fixture lab without exposing local project or desktop paths.
- Updated the PyPI publishing workflow so maintainers can manually dispatch a PyPI publish without rewriting an existing release tag.

## [4.0.1] - 2026-04-24

Public-launch release. Does not modify runtime behavior, profiles, catalog, evaluators, or report schemas shipped in `4.0.0`. Ships the formal public-release gate and supporting governance together with the first public publication of the repository. The `4.0.1-rc1` release-candidate tag was skipped in favor of promoting the validated candidate directly to `4.0.1`; see `docs/evidence-packs/2026-04-23-pre-freeze.md` and `docs/evidence-packs/2026-04-23-rc1-candidate.md` for the pre-promotion validation evidence.

### Added

- **Public release governance pack**: **`docs/public-release-readiness.md`** (hard gate for the first public repository launch), **`docs/publication-traceability-matrix.md`** (promise-to-evidence mapping, 16 rows at `GO` for this release), **`ROADMAP.md`** (public roadmap and maintenance governance), **`docs/public-launch-checklist.md`** (manual maintainer actions to execute against the frozen release commit), and **`.github/ISSUE_TEMPLATE/false_positive.yml`** (community false-positive reporting path with reproducibility requirements).
- **Evidence packs**: `docs/evidence-packs/2026-04-23-pre-freeze.md` (row-by-row validation against the pre-freeze working tree) and `docs/evidence-packs/2026-04-23-rc1-candidate.md` (post-bump confirmation of the build and validation pack). Both packs capture the validation performed before promoting the candidate directly to `4.0.1`.
- **Readiness test**: `tests/application/test_publication_readiness_assets.py` guards the four gate artifacts, cross-links from `README.md` / `docs/README.md` / `CONTRIBUTING.md`, reproducibility language in the false-positive template, and the absence of maintainer-local Windows paths in public docs.

### Changed

- **Public-facing docs**: `README.md`, `docs/README.md`, `docs/release-readiness.md`, and `CONTRIBUTING.md` now point to the public release gate, traceability matrix, roadmap, and false-positive handling workflow.
- **Repository hygiene**: `.gitignore` now covers maintainer-private planning artifacts (`/Crit*.txt`, `/Criterios*.txt`, `*.private.md`, `*.private.txt`) so `git add -A` cannot leak them during the freeze.

## [4.0.0] - 2026-04-23

### Breaking

- **`SEC-AUDIT-016`** and **`CI-SBOM-017`** are removed from the catalog and evaluator registry. External YAML profiles that still reference these IDs now raise **`ProfileLoadError`** with migration guidance pointing to **`docs/v4.0.0-migration-guide.md`**.
- **Default evaluation JSON contract moves to `reports/0.3`** (from `reports/0.2`). The payload adds **`summary_by_gate_role`** and **`gate_execution_model`** so CI consumers can reason about gate-relevant statuses without inferring semantics from aggregate counts. Use **`--report-json-contract 0.2`** only when you must preserve the previous wire shape.
- **`profiles --format json`** moves to **`oss-policy-kit/profile-list/v2`** and now exposes derived metadata including **`family`**, **`posture`**, and **`live_signal_posture`**. This is additive metadata only; bundled **`controls:`** lists are unchanged.

### Added

- **`docs/reports-contract-v0.3.md`** and **`src/oss_policy_kit/data/schema/evaluation-report-v3.schema.json`** document and validate the **`reports/0.3`** payload.
- **Profiles discovery filters**: **`profiles`** supports **`--family`** (`github`|`azure`|`aws`), **`--only-extreme`**, and **`--advisory-only`**.
- **`evaluate`** gained **`--quiet`** for parity with `evaluate-many`.
- **`docs/release-hardening-workflow.md`** adds an operational tutorial for L3 / release-hardening usage and evidence-backed flows.

### Changed

- **Publish workflow**: **`.github/workflows/publish-pypi.yml`** now pins third-party Actions to immutable commit SHAs (`actions/checkout`, `setup-python`, `upload-artifact`, `download-artifact`, `pypa/gh-action-pypi-publish`).
- **Azure and AWS collector hardening**: clearer permission and rate-limit handling, more explicit `nothing to collect` guidance, safer dry-run previews, and a stronger contract for synthetic vs live evidence without introducing new controls, profiles, or flags.
- **`collect-evidence --dry-run`** now prints environment probes for supported AWS and Azure variables as `set` / `not set` only, never values.
- **`evaluate-many`** now prints a one-line stderr summary when `skipped_directories` is non-empty, pointing to `evaluation-batch.json.skipped_directories` for the full list. It respects **`--quiet`** and does not change the batch JSON contract.
- **Legacy profile alias (`github-release-hardening`)** now emits a deprecation warning in favor of **`github-release-hardening-1`**.
- **`recommend-profile`** now restricts signal detection strictly to the passed **`--target`** and prefers **`github-level-1`** as the starter recommendation when governance evidence is not yet in place.
- **`diff-reports`** disables ANSI colors when stdout is not a TTY and its **`--help`** now carries explicit `EXAMPLES`, including the **`--fail-on-regression`** / **`--no-fail-on-regression`** pair.
- **`--fail-on degraded`** semantics are now spelled out consistently in help and public docs.
- **`--skip-non-repos`** help text now matches the real `is_likely_repository` logic.
- **`docs/v4.0.0-migration-guide.md`**, **`docs/profiles/deferred-followups.md`**, and **`docs/policy-data-lifecycle.md`** are aligned with the actual v4 cleanup and intended maturity fronts.

### Fixed

- CLI stdio is explicitly reconfigured to UTF-8 to avoid Windows `charmap` crashes under redirected output, with regression coverage for redirected I/O.
- ASCII dashes replace typographic dashes in CLI status messages for safer logs across Windows codepages.
- `scripts/consumer_smoke.py` now forces UTF-8 decoding for captured subprocess output on Windows, eliminating `UnicodeDecodeError` while preserving the expected smoke summary.

### Docs

- **`docs/profiles/overview.md`** now includes a ladder-model summary table of all 21 bundled profiles, a **`maturity_label`** glossary with recommended **`--fail-on`** by tier, a short note on why bare application repos tend to get uniform `*-level-1` output, and a clearer explanation of the hybrid advisory profiles.
- **`docs/profiles/aws.md`** and **`docs/profiles/azure.md`** now explain when each profile should be used, what `fail == 0` means and does not mean, and when synthetic evidence is enough versus when live collection is expected.
- **`docs/evidence-pack.md`** now includes a **`Dry-run security contract`** section stating that `collect-evidence --dry-run` prints only environment variable names and `set` / `not set` status, never values, and is safe for public CI logs.
- **`docs/adoption-guide.md`** now includes a **`Monorepo / multi-app`** subsection covering `evaluate-many`, the `--skip-non-repos` repo-root heuristic, `--include` / `--exclude`, and when to use `evaluate` directly per subtree.
- **`docs/packaging-and-release.md`** now makes the `v4.0.0` tag step explicit as a maintainer action.
- **`examples/hardened-repo/.oss-policy-kit/evidence/README.md`** now explains the synthetic evidence set file by file, including what synthetic `fail == 0` does and does not prove for AWS and Azure profiles.
- **`docs/profiles/deferred-followups.md`** continues to register the future conceptual gap placeholder discussed during release prep, but remains explicitly unscheduled.

## [3.3.0] - 2026-04-22

### Added

- **`tests/application/test_profile_bundle_invariants.py`**: guards that bundled profiles stay free of deprecated controls, that `AWS-CC-046` remains opt-in, that `BUILD-SBOM-QUAL-003` stays stable in the catalog, and that the hybrid profiles remain clearly advisory-only in their bundled metadata.
- **Profile maturity documentation**: `docs/profiles/overview.md` (21-profile matrix derived from `profiles --format json`, assurance vocabulary, ASCII decision tree), `docs/profiles/github.md`, `docs/profiles/aws.md`, `docs/profiles/azure.md`, and `docs/release-playbook-hardgate.md` (hard-gate release flow using only supported CLI commands).
- **`docs/profiles/deferred-followups.md`**: deferred follow-ups that would require new flags, report schema, or new controls (out of scope for this round).

### Changed

- **Release hygiene**: `.gitignore` now excludes `.cursorrules` and `.consumer-smoke-venv/`, `README.md` now points version-pinned install examples at `3.3.0`, and the maintainer release docs now make cleaning `dist/`, `build/`, and `.consumer-smoke-venv/` explicit before artifact validation.
- **README.md** and **docs/README.md**: link to the new profiles hub, per-family guides, and release hard-gate playbook.
- **Profiles docs clarity (consistency pass)**: `docs/profiles/overview.md` now includes an explicit operational usage matrix (`daily`, `extreme`, `advisory-only`, `legacy compatibility`) plus fixture representativity notes so users do not confuse fixture gaps with profile quality.
- **Family guides normalized**: `docs/profiles/github.md`, `docs/profiles/aws.md`, and `docs/profiles/azure.md` now use a consistent structure for daily vs extreme usage, evidence expectations, and honest maturity limits.
- **Recommend-profile honesty**: `README.md` now states that `recommend-profile` is heuristic guidance influenced by local evidence JSON, platform signals, and manifests/lockfiles, and must be confirmed with `evaluate`.
- **Hardened fixture positioning**: `examples/hardened-repo/README.md` now documents what the fixture is designed to validate, what it does not claim, and known representativity limits for `github-level-2`, `github-release-hardening-2`, `github-aws-level-2`, and `github-azure-level-2`.
- **Bundled `profile.yaml` descriptions**: light ladder “natural next step” sentences where helpful, without changing any `controls:` lists.
- **CLI `profiles` listing (public JSON surface)**: each profile row in `profiles --format json` now includes derived fields from bundled data + catalog: `maturity_label`, `assurance_mix`, `is_legacy_alias`, and `canonical_profile_id`. This is an additive contract for JSON consumers (table/human modes unchanged in spirit). The legacy id **`github-release-hardening`** stays supported; **`evaluate`** emits a **stderr** warning when that id is passed by name, and the JSON listing marks it as legacy/non-canonical next to **`github-release-hardening-1`**.
- **CLI compact presentation**: `profiles` compact mode now carries explicit audience/description text for hybrid advisory profiles (`github-aws-level-2`, `github-azure-level-2`) and keeps the legacy alias messaging for `github-release-hardening` clear and non-canonical.
- **`examples/hardened-repo`**: synthetic evidence and CI fixtures aligned with existing schemas so the six extreme profiles report **`summary_by_status.fail == 0`** in tests and fixture smoke runs — explicitly **not** the same as every control being `pass` (expect `self-attested`, `not-evaluated`, and operational warnings; AWS/Azure skew more self-attested than GitHub in this synthetic tree). **`.gitignore`**: `.oss-policy-kit/` remains ignored everywhere except **`examples/hardened-repo/.oss-policy-kit/evidence/**`** (via root negated patterns). **`examples/hardened-repo/.oss-policy-kit/.gitignore`** keeps sibling junk under that directory untracked so only `evidence/` is meant to ship.

### Fixed

- **Packaging validation helpers**: `scripts/consumer_smoke.py` and `scripts/twine_check_dist.py` now resolve artifacts that match the current `pyproject.toml` version instead of trusting the last wheel in a broad glob or checking every leftover file under `dist/`.
- **Windows human profile listing**: `python -m oss_policy_kit --show-profiles` and `python -m oss_policy_kit profiles` no longer crash under legacy `cp1252` terminals due to the legacy alias arrow glyph; the display now uses ASCII `->` for compatibility.
- **Docs encoding**: restored `docs/profiles/*.md` that had been corrupted by shell escaping (control characters in place of `*` / `a` in words).

## [3.2.0] — 2026-04-20

### Added

- **`docs/v4.0.0-migration-guide.md`**: documents the removal plan for deprecated controls `SEC-AUDIT-016` and `CI-SBOM-017` in v4.0.0, replacement control recommendations per platform, custom profile migration instructions, and summary of assurance upgrades shipped in v3.x.
- **`tests/application/test_docs_consistency.py`**: regression tests that `github-level-1` remains 14 active controls and that key public docs do not reintroduce retired baseline phrasing.
- **GitHub `collect-evidence` (`--platform github`)**: API-produced evidence for branch protection, rulesets, environment protection, and secret scanning now includes a `collection` object with `evidence_collection_method: live`, `collected_at` (UTC ISO-8601), `source_url`, and `mode: api`, and uses `attested_by: github-api-collection` for these live files.
- **AWS `collect-evidence` (`--platform aws`)**: `aws-codecommit-review-posture.json` now includes a `collection` object for live API collection of CodeCommit review posture.

### Changed

- **Public documentation** (commit `44d6704`): `README.md`, `docs/adoption-guide.md`, `docs/evidence-pack.md`, `docs/policy-data-lifecycle.md`, `docs/recommended-adoption-playbook.md`, and `examples/hardened-repo/README.md` now match the current `github-level-1` baseline (14 active controls, 67 catalogued controls, revision-dependent self-check expectations) and no longer use retired `pass: 16` / `63 passed` / `all 62 bundled` phrasing; the recommended template path no longer positions deprecated audit/SBOM YAML controls as the primary adoption gate.
- **API-backed evidence detection** (`_evidence_is_api_backed()` / report metadata): `github-api-collection` is treated as API-backed together with `aws-api-collection` and `azure-devops-api-collection`. A `collection` object with `evidence_collection_method: live` or `mode: api` is also treated as live collection.
- **PLAT-BRPROT-015** and **GH-PLAT-024 / GH-PLAT-025 / GH-PLAT-026**: evaluation sets `evidence_collection_method` to **`live`** when GitHub/API evidence JSON includes live collection metadata, and **`manual`** for self-attested or scaffold files; PASS/FAIL / missing-evidence semantics are unchanged. Reasons distinguish live collection versus self-attested wording where relevant.
- **Evidence JSON schemas** (`src/oss_policy_kit/data/schema/` mirrored under `reports/schema/` for the touched files): optional `collection` object validated for GitHub branch protection, rulesets, environment protection, secret scanning, and AWS CodeCommit review posture payloads.
- **GH-WF-018** reclassified from `signal`/`partially_observable` to `deterministic`/`automated`: `secrets: inherit` detection now uses the structural YAML parse (`job.get("secrets") == "inherit"`) instead of raw-string substring matching, eliminating false positives from YAML comments.
- **AZ-PIPE-028** reclassified from `signal`/`partially_observable` to `deterministic`/`automated`: PR trigger detection now relies exclusively on `data.get("pr") is not None` from the parsed YAML document, removing the previous `"pr:" in raw_lower` substring check that could match comment lines or string values.
- **CI-LEAST-009** `_SENSITIVE_FOR_LEAST_PRIV` expanded with OSS publish patterns: `twine upload`, `npm publish`, `cargo publish`, and `pypi publish` — jobs that publish packages without explicit `permissions:` are now flagged. These are high-value targets in OSS release workflows that require write tokens.
- **GH-DEPLOY-022** OIDC detection expanded with provider-specific structural checks: `aws-actions/configure-aws-credentials` + `role-to-assume:` in `with:` block, `google-github-actions/auth` + `workload_identity_provider:` in `with:` block, and `azure/login` + `client-id:` without `creds:` are now recognised as OIDC federation patterns.
- **GH-PROV-023** provenance/attestation regex expanded to cover `slsa-framework/slsa-github-generator`, `sigstore/cosign-installer`, and `cosign sign` run steps in addition to the existing `actions/attest-build-provenance`, `slsa`, `provenance`, and `attestation` patterns.
- **PLAT-BRPROT-015** is **evidence-backed** in the catalog: without `.oss-policy-kit/evidence/branch-protection.json` the evaluator returns **`not-evaluated`** (no local PASS heuristics). Valid evidence yields **PASS** with schema validation.
- **GH-PLAT-024 / GH-PLAT-025 / GH-PLAT-026**: missing evidence files → **`not-evaluated`**; invalid schema → **FAIL**; strict posture satisfied → **PASS**; incomplete posture → **FAIL**; placeholder tokens in JSON → **`not-evaluated`** (unchanged placeholder policy).
- **CI-LEAST-009**: fails when `implicit_permission_risks` detects **actions/checkout** with non-default **`token`** or sensitive **run** patterns (e.g. `docker push`, `gh release`, cloud deploy) **without** explicit job-level `permissions:` (and related top-level gaps), as described in `workflow_parser`.
- **SEC-CODEQL-010** / **SEC-SECRETS-050**: broader keyword / regex coverage for additional SAST and secret-scanning tools in workflow YAML.
- **Azure / AWS collectors**: documented PAT vs IAM expectations in `collect()` docstrings and `docs/evidence-pack.md`; added **no-op** `collect_sbom_artifact` / `collect_provenance_artifact` hooks (manual-only for AZ-ARTSBOM-058, AZ-ARTPRV-059, AWS-SBOMART-058, AWS-PROVART-059) with integration tests.
- **Catalog assurance upgrades**: `AZ-PIPE-029`, `AZ-PIPE-030`, `GH-WF-019`, and `GH-WF-020` reclassified from `signal`/`partially_observable` to `deterministic`/`automated`. Analysis confirmed their evaluators perform structural YAML parse (not keyword matching): `persist_credentials_true_paths` and `extends_template_paths` in the Azure pipeline parser use `step.get("persistCredentials")` and `"extends" in data`; `pr_self_hosted_runner_paths` and `broad_job_permissions` in the GitHub workflow parser use structured `job.get("runs-on")` and `job.get("permissions")`.
- **Deprecated evaluators now return `NOT_EVALUATED`**: `eval_sec_audit_016` (SEC-AUDIT-016) and `eval_ci_sbom_017` (CI-SBOM-017) no longer emit PASS or FAIL. Both return `NOT_EVALUATED` with a deprecation message and migration guidance. No bundled profile includes these controls; custom profiles that still reference them will see `NOT_EVALUATED` in reports.
- **`docs/policy-data-lifecycle.md`**: rewritten for the current catalog (including control counts and lifecycle story); aligned again in the documentation pass above for starter-baseline wording.

### Deprecation notice (v4.0.0 removal planned)

- **SEC-AUDIT-016** (`deprecated`): will be removed in v4.0.0. Evaluator currently returns `NOT_EVALUATED`. Recommended replacements: `SEC-CODEQL-010`, `SEC-SECRETS-050`, `BUILD-SBOM-QUAL-003`. See `docs/v4.0.0-migration-guide.md`.
- **CI-SBOM-017** (`deprecated`): will be removed in v4.0.0. Evaluator currently returns `NOT_EVALUATED`. Recommended replacements: `BUILD-SBOM-QUAL-003`, `GH-PROV-023`, `AWS-SBOMART-058`, `AZ-ARTSBOM-058`. See `docs/v4.0.0-migration-guide.md`.

## [3.1.0] — 2026-04-17

### Added

- **Evidence JSON schemas** (mirrored under `src/oss_policy_kit/data/schema/` and `reports/schema/`): `evidence-aws-sbom-artifact`, `evidence-aws-provenance-artifact`, `evidence-azure-sbom-artifact`, `evidence-azure-provenance-artifact`, `evidence-org-mfa-posture`.
- **Bundled multi-platform advisory profiles**: `github-aws-level-2` (GitHub SCM + AWS CodeBuild/CodePipeline signals) and `github-azure-level-2` (GitHub SCM + Azure Pipelines signals).
- **`tests/application/test_catalog_assurance.py`**: regression coverage for catalog **`assurance`** values and per-result projection in **`reports/0.2`** JSON.

### Changed

- **Evaluator maturity (signals vs proof)**: `is_placeholder_digest()` rejects toy/template SHA-256 digests in artifact-bound evidence; Azure governance rejects `authentication: unknown` on service connections; lowered inflated **confidence** on YAML/text fallbacks (for example **AZ-IDENT-036**, **AWS-PIPEIAM-056**, **AWS-CBIDENT-057**, keyword-pass controls **AZ-SEC/SBOM/SCA-031..033** and **AWS-SEC/SBOM/SCA-039..041**); **GOV-WAIV-014** yields **`manual-review-required`** when no versioned in-repo waiver policy is found; **PLAT-BRPROT-015** without branch-protection evidence → **`manual-review-required`** (invalid/missing flags in a present file remain **`fail`**); GitHub **GH-PROV-023**, **GH-DEPLOY-022**, and **GH-REL-021** add **`not-applicable`** heuristics where no deploy/release workflows apply, **GH-DEPLOY-022** fails on long-lived cloud secret patterns, **GH-REL-021** documents concurrency examples; **AZ-WIFEV-057** requires explicit **`posture.federated_identity_preferred`**; **BUILD-SBOM-QUAL-003** keyword-only CI without SBOM file → **`manual-review-required`**; **ORG-MFA-001** fail reasons and SSO warning refined; **CI-WFCALLSHA-055** validates reusable **`uses:`** pins from parsed workflow YAML; **GOV-EVIDFRESH-054** emits an operational warning when evidence is close to the max-age window.
- **Azure profiles**: `azure-level-1`/**starter**, `azure-level-2`/**advisory**, `azure-level-3`/**hard-gate** (deterministic + evidence-backed core: **GOV-EVIDFRESH-054**, **AZ-PLAT-034/035**, **AZ-SCONN-056**, **AZ-WIFEV-057**, **AZ-ARTSBOM-058**, **AZ-ARTPRV-059**; **AZ-SEC/SBOM/SCA-031..033** intentionally excluded from the level-3 gate); **`azure-release-hardening-3`** stacks the hard-gate core plus the **031..033** signal bundle for release visibility.
- **AWS profiles**: `aws-level-1`/**starter**, `aws-level-2`/**advisory**, `aws-level-3`/**hard-gate** (evidence-backed core; no buildspec-only signal bundle); **`aws-release-hardening-3`** stacks level-3 hardening plus release-time signals; optional **CodeCommit** is not required on **`aws-level-3`**.
- **AWS controls**: structural buildspec env parsing and stricter committed **CodePipeline** export validation (**`AWS-PIPE-042`**); **`AWS-SECRET-038`** is **deterministic** in the catalog; **`AWS-CP-044`** / **`AWS-CB-045`** / **`AWS-CC-046`** may **`pass`** with **`evidence_collection_method: live`** when API-collected evidence is present; **`AWS-PIPEIAM-056`**, **`AWS-CBIDENT-057`**, **`AWS-SBOMART-058`**, **`AWS-PROVART-059`** ship with JSON schemas and **`collect-evidence`** metadata (`collection`, `iam`, `identity`).
- **GOV-EVIDFRESH-054**: freshness stamp may be read from **`collection.collected_at`** on evidence objects.

### Fixed

- Artifact-bound SBOM/provenance evaluators no longer treat obvious template digests as strong proof.

## [3.0.1] — 2026-04-17

### Added

- **Catalog `assurance`**: per-control maturity of proof — `deterministic`, `signal`, or `evidence-backed` — loaded via `ControlSpec`, emitted on **`reports/0.2`** results as `assurance`, and shown in Markdown tables.
- **Controls** `GH-MERGEQ-053` (merge queue / `merge_group` signal), `GOV-EVIDFRESH-054` (evidence JSON freshness under `.oss-policy-kit/evidence/`), `CI-WFCALLSHA-055` (reusable workflow calls must use full 40-char SHA pins).
- **Matrix**: private maintainer planning matrix covering control_id, lifecycle, automation, assurance, and profile guidance.
- **Azure `collect-evidence`**: pipeline governance payload now consults **serviceendpoint/endpoints** for workload federation vs PAT-style connections when the API succeeds; conservative `false` when data is missing or ambiguous.
- **AWS `collect-evidence`**: CodeBuild evidence includes optional **`codebuild_service_role_configured`** (IAM role ARN present); **`aws-level-3`** / **`aws-release-hardening-3`** require it for **`AWS-CB-045`** when evaluating strict profiles.

### Changed

- **GitHub profiles**: `github-level-1` **starter** (14 controls, no deprecated `SEC-AUDIT-016` / `CI-SBOM-017` in profile lists); `github-level-2` **advisory**; `github-level-3` **hard-gate** (evidence-first; drops weak-only `GH-DEPLOY-022`, `GH-PROV-023`, `SEC-SECRETS-050` from the gate set). Release-hardening tracks updated accordingly; **`github-release-hardening`** remains a **legacy bundled id** resolved from **`github-release-hardening-1`** with the same control set.
- **Azure / AWS ladders**: `azure-level-3` includes **`AZ-PLAT-034`**/**`035`**; `aws-level-3` adds **`AWS-CP-044`**/**`AWS-CB-045`**; release-hardening-3 tracks add **`GOV-EVIDFRESH-054`** where listed.
- **Docs**: adoption guide, README (assurance row), release readiness, and recommended playbook counts aligned with the starter baseline (**14** passes).

## [3.0.0] — 2026-04-18

### Breaking changes

- **Report JSON contract** defaults to **`reports/0.2`**. New top-level field **`live_collection`** (nullable object) and per-result **`evidence_collection_method`** (`live` \| `manual` \| `static`). Optional **`deprecation_note`** on results when the catalog marks a deprecated control. Use **`evaluate --report-json-contract 0.1`** (or the same flag on the root compatibility invocation) to emit the legacy **`reports/0.1`** shape for strict downstream parsers.
- **`EVALUATOR_REGISTRY`** now loads third-party callables from the **`oss_policy_kit.evaluators`** entry-point group after built-ins are registered; duplicate control IDs raise at import time.

### Added

- **`collect-evidence`**: API-backed collection into **`.oss-policy-kit/evidence/`** for **`github`** (**`GITHUB_TOKEN`**, **`oss-policy-kit[github]`** / **`httpx`**), **`azure`** (**`AZURE_DEVOPS_ORG`**, **`AZURE_DEVOPS_TOKEN`**, **`--repo Project/repo`**), and **`aws`** (**`oss-policy-kit[aws]`** / **`boto3`**; optional **`AWS_CODEBUILD_PROJECT`**, **`AWS_CODEPIPELINE_NAME`**, and/or **`--repo`** CodeCommit repository name).
- **`diff-reports`**: compare two **`evaluation-report.json`** files; **`--fail-on-regression`** (default) exits **1** on regressions (**`pass`** / **`self-attested`** → **`fail`**).
- **External profiles**: **`--profile`** may be a path to a YAML file validated with **`profile-spec.schema.json`** (**`ProfileLoadError`** on failure).
- Packaged schema **`evaluation-report-v2.schema.json`**; public **`reports/schema/evaluation-result.schema.json`** updated for v0.2 fields.
- Optional extras: **`github`**, **`azure`**, **`aws`**, **`all`** in **`pyproject.toml`**.
- **`evaluate` (formato human)**: tabela Rich no stdout com resumo por estado e caminho do alvo.
- **`collect-evidence --dry-run`**: pré-visualização do plano de recolha **antes** de validar tokens ou credenciais.
- **`diff-reports`**: deteção de **`profile_id`** diferente entre relatórios; aviso em stderr e nota no relatório Markdown/JSON.
- **`evidence_placeholders`**: deteção de valores de evidência ainda com tokens de scaffold (**`REPLACE_ME`**, **`YYYY-MM-DD`**, etc.) com aviso operacional na avaliação.
- **`ProfileLoadError`**: mensagens com dicas quando o YAML externo falha validação (ex.: **`id`** em falta, **`controls`** com tipos incorretos).
- Testes: **`test_evidence_placeholders`**, heurística de repositório sem README isolado, drift com **`profile_mismatch`**; **`tests/cli/test_diff_reports_subprocess.py`** (exit codes **2** / **1** / **0**); **`tests/unit/test_drift.py`** (melhoria **fail → self-attested**).

### Changed

- **Catalog**: many controls promoted from **`experimental`** to **`stable`**; **`SEC-AUDIT-016`** and **`CI-SBOM-017`** marked **`deprecated`** with **`deprecation_note`**. **`GH-PLAT-024`–`026`** promoted to **`stable`** after GitHub evidence automation. **`AZ-PLAT-034`**, **`AZ-PLAT-035`**, **`AWS-CP-044`**, and **`AWS-CC-046`** promoted to **`stable`** after Azure/AWS **`collect-evidence`** collectors.
- **`scaffold-evidence`** documentation reframed as **manual** evidence mode; **`collect-evidence`** is the API-backed path.
- **`is_likely_repository`**: README sozinho já **não** conta como raiz de repositório; sinais fortes incluem **`.git`**, manifests, CI, Docker, lockfiles.
- **`--verbose`**: saída de diagnóstico no **stdout** (consola Rich dedicada).
- **`terminal_ui.build_console` / `build_stdout_console`**: respeito a **`NO_COLOR`**, **`TERM=dumb`** e TTY para Rich (`force_terminal` / `no_color` coerentes com pipe).
- **`--profile`**: texto de help alargado (caminho para YAML externo validado por schema).

### Fixed

- **`evaluate`** (saída human Rich no stdout): em Windows com codepages estreitas, a tabela de resultados usa o mesmo fallback UTF-8 via **`.buffer`** que **`diff-reports`**, evitando **`UnicodeEncodeError`** em ícones de estado (ex.: ✓).
- **`diff-reports`**: stdout em Windows (codepages estreitas) — escrita com fallback UTF-8 via **`.buffer`** quando o texto Rich não cabe na codepage do consola; testes de subprocesso passam **`encoding=utf-8`** na captura.

## [2.0.1] - 2026-04-17

### Summary

Release **2.0.1** closes the remaining release blockers from the 2.0.0 hardening work: PyPI publish artifacts now keep SBOM output separate from wheel/sdist files, and `recommend-profile` now recognizes the documented Azure pipeline layouts under nested directories.

### Fixed

- **PyPI publish workflow / SBOM**: `publish-pypi.yml` now writes the CycloneDX SBOM to **`artifacts/sbom.cyclonedx.json`** instead of **`dist/`**, keeping the distribution artifact clean for **`twine check`**, TestPyPI, and PyPI publish jobs.
- **`recommend-profile` Azure detection**: `_azure_pipeline_paths()` now recognizes **`pipelines/azure/*.yml`**, **`pipelines/azure/*.yaml`**, **`.azure-pipelines/*.yml`**, and **`.azure-pipelines/*.yaml`**, matching the parser and documented support matrix.
- Added regression coverage for nested Azure layouts and the publish workflow artifact structure.

### Changed

- Release-readiness documentation now reflects the dedicated SBOM artifact path outside **`dist/`**.

---

## [2.0.0] - 2026-04-15

### Summary

Release **2.0.0** aligns package metadata with the codebase, strengthens batch and CLI ergonomics, adds experimental supply-chain governance controls, tech-stack aware profile hints, CI templates, SBOM generation in publishing, and clearer waiver semantics.

### Added

- Control status **`not-evaluated`** for cases where a control cannot be meaningfully asserted from a clone (used by **`GOV-WAIV-014`** when no versioned in-repo waiver file exists).
- Experimental controls **`SEC-SECRETS-050`**, **`SEC-GITIGNORE-051`**, **`SEC-PINLOCK-052`** (`lifecycle: experimental`), included on **`github-level-2`** and **`github-level-3`** profiles.
- **`evaluate-many`**: `--fail-on` (CI gate across batch runs), `--skip-non-repos`, `--quiet`, stderr progress lines, batch JSON fields **`gate_violated`**, **`fail_on`**, **`all_tied`**, **`common_fail_count`**, **`failure_distribution`**, optional **`skipped_directories`**.
- **`evaluate`**: **`--verbose`** / **`-v`** (per-control dim lines on stderr).
- **`--format`** aliases: **`evaluate`** accepts `table`, `compact`, `detailed` (human layout); **`profiles`** accepts `human`, `verbose`; **`recommend-profile`** accepts `table`, `compact`.
- **`recommend-profile`**: tech-stack signals (Node, Python, Go, Java, Rust, .NET, containers) with **`github-level-2`** preference when container files are present; optional notes for lockfiles and **`pyproject.toml`** quality tools.
- JSON schema documentation: **`src/oss_policy_kit/data/schema/profile-recommendation-v2.schema.json`**.
- GitHub Actions templates under **`templates/workflows/`**: baseline, waivers variant, and **`github-level-2`** variant.
- Dev dependency **`cyclonedx-bom`** and SBOM step in **`.github/workflows/publish-pypi.yml`** (`dist/sbom.cyclonedx.json`).
- **`evaluate --format json`**: stderr confirmation **`Reports written to: …`** without polluting stdout JSON.

### Changed

- **`GOV-WAIV-014`**: missing versioned **`waivers/*.yaml`** now yields **`not-evaluated`** with updated reason text (no implied self-attestation).
- Batch Markdown: failure distribution table, CI gate line, tie message when all targets share the same fail count, skipped-directory section when **`--skip-non-repos`** applies.
- Documentation: README **CI/CD Integration**, **`docs/adoption-guide.md`** CI notes and **`--format json`** stderr behavior; **`docs/release-readiness.md`** SBOM checklist items.

### Fixed

- **`recommend-profile`**: **`_collect_signals`** call restored to pass **`aws_ev`** (regression fix).

---

## [1.0.2] - 2026-04-14

### Summary

This release improves onboarding consistency and strengthens report stability.

### Added

- Added a recommended adoption path to support more consistent project onboarding.
- Expanded quality coverage to improve report consistency across usage scenarios.

### Changed

- Improved CLI summary readability and output consistency.
- Updated examples and documentation to better reflect the recommended adoption flow.

---

## [1.0.1] - 2026-04-13

### Summary

This release improves documentation quality, adoption guidance, and overall project usability.

### Added

- Expanded release and maintainer guidance.
- Added and improved templates to support broader adoption scenarios.

### Changed

- Refined setup, adoption, validation, and project site documentation.
- Improved repository hygiene for local and generated artifacts.
- Enhanced project site readability and presentation.

### Fixed

- Improved CI/CD workflow consistency and reliability.
- Corrected packaging and automation details for better operational stability.

---

## [1.0.0] - 2026-04-13

### Summary

First stable major release of the project, providing a packaged CLI, bundled policy content, and maintainable automation for adoption and evaluation workflows.

### Added

- First stable major release line for the project.
- CLI version reporting support.

### Changed

- Aligned package versioning and metadata for a stable public release.
- Updated public documentation to reflect the current project structure and workflow model.

### Fixed

- Improved workflow consistency and automation baseline quality.
- Strengthened repository self-validation and release readiness.

---

## [0.4.0] - 2026-04-11

### Summary

This release expands policy maturity visibility, strengthens supply chain coverage, and improves reporting and platform support.

### Added

- Added policy lifecycle visibility to better communicate control maturity.
- Introduced experimental controls for security and software supply chain coverage.
- Expanded branch protection evidence support.
- Added support for software bill of materials and build provenance scenarios.
- Expanded CI execution coverage across environments.
- Added coverage reporting support.
- Expanded documentation related to trust model and dependency guidance.

### Changed

- Improved lifecycle documentation and reporting outputs.
- Refined remediation guidance and hardened example expectations.

### Notes

- Experimental controls introduced in this release may continue to evolve.
- Report outputs generated from earlier versions may need to be regenerated for full compatibility.

---

## [0.3.0] - 2026-04-10

### Summary

This release improves packaging readiness, CLI behavior, and automated quality coverage.

### Added

- Added packaging workflows for building and validating release artifacts.
- Added packaging and lifecycle documentation.
- Expanded CLI automation with improved output and failure-handling behavior.
- Added broader automated coverage for reports, summaries, and CLI flows.

### Changed

- Improved project packaging structure and release readiness.
- Updated documentation to support packaging and release usage.

---

## [0.2.0] - 2026-04-10

### Summary

This release reorganizes the project for a packaged structure and improves maintainability.

### Changed

- Moved the control catalog and bundled profiles into the packaged project structure.
- Reorganized tests by architecture layer.
- Refreshed CI workflows, contributor guidance, and architecture/adoption documentation for the packaged layout.

### Removed

- Removed legacy root-level structures replaced by the packaged project organization.

---

## [0.1.0] - 2026-04-10

### Summary

Initial publishable MVP of the project, introducing the CLI, bundled policy content, reporting, and baseline automation.

### Added

- Initial publishable CLI release.
- Bundled catalog and evaluation profiles.
- Markdown and JSON reporting support.
- JSON Schema support.
- Initial controls for governance, workflow hygiene, security signals, disclosure posture, and branch protection.
- Example repositories for different evaluation scenarios.
- Templates for documentation and workflows.
- Waiver support.
- Automated tests and CI workflows.
- Initial repository hardening measures.
- Cross-platform documentation improvements.

### Notes

- Some platform-level checks may still require supplemental evidence depending on the execution environment.
