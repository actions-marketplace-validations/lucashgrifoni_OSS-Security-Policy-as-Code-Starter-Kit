# Changelog

All notable public changes to this project are summarized here.

This changelog follows the same public-facing format used by the GitHub release notes. It intentionally focuses on release outcomes, user-facing changes, and adoption impact instead of internal implementation logs.

---

## OSS Security Policy as Code Starter Kit v4.0.3

This patch release improves public repository hygiene for Azure Pipelines by moving the project pipeline into the supported `pipelines/azure/` layout, reducing unnecessary platform metadata exposure, and aligning detection, documentation, and CLI messaging with that organized structure.

---

### Highlights

- Moved the project Azure Pipelines definition from the repository root into `pipelines/azure/`
- Kept the public Azure YAML free of secrets, tenant identifiers, subscription identifiers, service connection details, internal URLs, private IPs, local paths, and specific machine names
- Updated repository discovery so `evaluate-many --skip-non-repos` recognizes supported nested Azure pipeline layouts
- Improved profile recommendation and terminal wording for Azure pipeline detection
- Normalized synthetic Azure fixture names so examples do not look like real production service connections

---

### Improvements

- Cleaner public repository structure for multi-platform CI evidence
- Better alignment between Azure documentation, parser support, profile recommendation, and batch repository detection
- Lower metadata noise in public fixtures and CI examples
- Added regression coverage for nested Azure pipeline repository detection
- Revalidated GitHub and Azure self-checks, targeted Azure tests, linting, typing, and secret/provenance hygiene scans

---

### Notes

- This is a patch release in the 4.0.x line
- Users running the provided Azure DevOps pipeline should update the pipeline YAML path to `pipelines/azure/azure-pipelines.yml`
- No report schema, bundled profile, control catalog, evaluator scoring, or packaged policy data changes are introduced
- The v4.0.2 tag remains immutable and is not moved

---

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.2

This patch release consolidates documentation, release hygiene, and CI hygiene improvements that landed after v4.0.1. It does not change runtime behavior, bundled profiles, the control catalog, evaluator logic, CLI flags, report schemas, or packaged policy data.

---

### Highlights

- Updated public launch documentation to reflect the current release state
- Added sanitized real CI screenshots for GitHub Actions and Azure Pipelines self-check flows
- Improved workflow self-check commands to use the supported `evaluate` subcommand
- Refined Azure Pipelines execution hygiene with pip caching and shallow checkout behavior
- Preserved the v4.0.1 release as immutable while promoting the current public repository state into v4.0.2

---

### Improvements

- Better public release traceability between README, screenshots, CI examples, and repository state
- Clearer documentation of what is included in the public repository and what remains outside the public mirror
- Improved CI example accuracy through real sanitized pass/fail self-check evidence
- Cleaner repository hygiene through safer ignore patterns for maintainer-private working notes
- Improved cross-platform CLI test stability by avoiding Linux-specific path assumptions in test expectations

---

### Notes

- This is a patch release in the 4.0.x line
- No runtime, schema, CLI, control, evaluator, or bundled profile behavior changes are introduced relative to v4.0.1
- The v4.0.1 tag remains immutable and is not moved
- This release focuses on publication readiness, documentation accuracy, CI hygiene, and release traceability

---

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.1

This public-launch patch release promotes the validated launch candidate into the official 4.0.1 release without changing runtime behavior, bundled profiles, control catalog, evaluator logic, CLI flags, report schemas, or packaged policy data.

### Highlights

- First public-launch release package for the repository governance layer
- Added formal public release readiness, traceability, and launch checklist artifacts
- Included evidence packs covering pre-freeze and RC1 candidate validation
- Added roadmap and post-publication governance assets
- Strengthened publication readiness with regression guardrails and false-positive issue intake support

### Improvements

- Better publication governance through formal release-readiness and launch checklist documentation
- Improved traceability with a dedicated publication traceability matrix
- Stronger release evidence with pre-freeze and RC1 candidate validation packs
- Better public maintenance posture through roadmap and post-publication governance documentation
- Improved operational readiness with a false-positive issue template for public feedback handling
- Continued workflow hygiene by keeping action references pinned to immutable SHAs
- Improved repository consistency through documentation refreshes and formatting normalization without semantic runtime changes

### Notes

- This is a public-launch patch release in the 4.0.x line
- No runtime, schema, CLI, control, evaluator, or bundled profile behavior changes are introduced relative to the validated 4.0.0 candidate
- The v4.0.1 RC1 tag was intentionally skipped in favor of promoting the validated candidate directly to v4.0.1
- Validation evidence is captured in the repository evidence packs and includes tests, linting, formatting, typing, packaging, smoke validation, self-check execution, and external validation reruns

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v4.0.0

This major release advances the kit with a new report contract, cleaner profile discovery, stronger collector hardening, and a more explicit migration path, while removing deprecated controls and tightening operational behavior across evaluation and evidence workflows.

### Highlights

- Introduced the new default evaluation JSON contract `reports/v0.3`
- Removed deprecated controls and aligned external profile migration behavior
- Improved profile discovery with richer derived metadata and new filtering options
- Strengthened Azure and AWS collector hardening and dry-run safety
- Expanded release-hardening and evidence-backed workflow documentation
- Improved cross-platform CLI reliability, including safer Windows output handling

### Improvements

- Better reporting clarity through gate-oriented metadata in the new `reports/v0.3` contract
- Stronger profile usability with additive metadata such as family, posture, and live-signal posture
- Improved profile discovery via family, advisory-only, and extreme-only filtering
- Better collector safety with clearer permission guidance, safer dry-run previews, and stronger handling of synthetic versus live evidence
- Improved batch evaluation usability with clearer skipped-directory summaries that preserve JSON contract stability
- Better recommendation behavior by restricting signal detection to the evaluated target and preferring safer starter guidance when governance evidence is missing
- Improved diff reporting and fail-on behavior with clearer ANSI and help semantics
- Better documentation alignment across migration guidance, profile docs, lifecycle guidance, evidence packs, adoption notes, and release-hardening usage
- Stronger packaging and publishing hygiene through immutable SHA pinning in the publish workflow
- Improved Windows reliability through UTF-8 stdio reconfiguration, safer ASCII status messages, and more robust smoke validation output handling

### Notes

- This is a major release and introduces the new default report contract `reports/v0.3`
- Users who need the previous JSON wire shape should continue using `--report-json-contract 0.2`
- Deprecated controls `SEC-AUDIT-016` and `CI-SBOM-017` are now removed from the catalog and evaluator registry
- External YAML profiles that still reference removed controls now fail fast with migration guidance
- This release focuses on contract clarity, collector hardening, migration readiness, and more predictable operational behavior across platforms

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.3.0

This release improves profile documentation clarity, strengthens bundled profile stability, and hardens packaging and validation workflows for more reliable release operations across platforms.

### Highlights

- Added regression coverage to lock bundled profile invariants and keep hybrid advisory metadata stable
- Expanded profile maturity documentation across profile guides and the release playbook
- Improved the public `profiles --format json` surface with richer additive metadata
- Hardened packaging validation so release checks resolve artifacts for the current project version
- Improved Windows compatibility for human-readable profile listing output

### Improvements

- Better bundled profile stability through invariant-focused regression testing
- Improved profile guidance with clearer operational usage classes and more honest `recommend-profile` messaging
- Better automation support through additive profile metadata such as maturity labels, assurance mix, legacy alias markers, and canonical profile identifiers
- Improved compact profile listing text for hybrid advisory profiles and legacy alias messaging
- Stronger release hygiene with explicit cleanup guidance for distribution and consumer smoke validation directories
- Better release documentation while intentionally keeping bundled profile controls unchanged
- Expanded follow-up documentation for work intentionally deferred from this release

### Notes

- This release focuses on profile maturity clarity, release hygiene, and packaging reliability
- Bundled profile controls remain unchanged in this version
- Packaging validation now resolves artifacts against the active `pyproject.toml` version instead of trusting stale files in `dist/`
- Includes Windows compatibility and documentation encoding fixes for a smoother cross-platform experience

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.2.0

This release improves evidence-backed evaluation, strengthens documentation and migration guidance, refines platform control behavior, and prepares the path for the planned v4.0.0 deprecations.

### Highlights

- Added a dedicated v4.0.0 migration guide covering deprecated controls, replacement paths, and custom profile migration
- Expanded API-backed evidence collection metadata for GitHub and AWS live collection flows
- Improved evaluator behavior across GitHub, Azure, and AWS with stronger structural validation and clearer evidence semantics
- Tightened control logic to reduce false positives and better distinguish deterministic proof from weaker signals
- Clarified the deprecation path for older audit and SBOM-related controls ahead of v4.0.0

### Improvements

- Better migration readiness through a dedicated upgrade guide and clearer deprecation messaging
- Improved documentation consistency across README, adoption guidance, evidence pack guidance, lifecycle notes, and hardened example references
- Stronger API-backed evidence handling with richer `collection` metadata, including collection method, timestamps, source URL, and attested model context
- Better PLAT and GH evaluator behavior by distinguishing live API-collected evidence from self-attested or scaffolded files
- Improved schema validation and evidence handling for branch protection, rulesets, environment protection, secret scanning, and AWS CodeCommit review posture
- Stronger GitHub workflow evaluation with more structural parsing and broader OIDC, provenance, least-privilege, SAST, and secret-scanning detection
- Improved Azure and AWS collectors with clearer credential expectations and manual-only hooks for artifact and provenance collection paths
- Better catalog assurance and parser behavior through more deterministic workflow and pipeline analysis
- Clearer control lifecycle handling as deprecated evaluators now return `NOT_EVALUATED` with migration guidance instead of misleading pass/fail results

### Notes

- This release prepares users for the planned v4.0.0 removal of `SEC-AUDIT-016` and `CI-SBOM-017`
- Deprecated controls now surface migration-oriented behavior and should be replaced with the recommended platform-specific alternatives
- Focused on evaluator accuracy, evidence trust boundaries, documentation clarity, and upgrade readiness
- Continues strengthening the distinction between live API-backed proof, manual evidence, and not-yet-evaluable placeholder inputs

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.1.0

This release improves evidence validation maturity, expands advisory profile coverage, and strengthens Azure and AWS posture evaluation with more reliable proof handling and clearer confidence boundaries.

### Highlights

- Added new evidence JSON schemas for AWS and Azure SBOM and provenance artifacts
- Introduced bundled multi-platform advisory profiles for GitHub + AWS and GitHub + Azure scenarios
- Expanded regression coverage for catalog assurance values and `reports/0.2` result projection
- Improved evaluator maturity by tightening the distinction between weak signals and stronger proof

### Improvements

- Better evidence quality by rejecting obvious placeholder or template digests in artifact-bound validation
- Improved Azure governance evaluation with stricter service connection and YAML evidence handling
- Stronger waiver and branch-protection behavior with clearer manual-review-required outcomes when proof is missing or incomplete
- Better Azure profile progression across starter, advisory, hard-gate, and release-hardening tracks
- Improved AWS profile structure with clearer hard-gate and release-hardening expectations
- Stronger AWS control evaluation through stricter CodePipeline export validation and better live evidence handling
- Better freshness handling through support for `collection.collected_at` on evidence objects
- Improved reliability for artifact-bound SBOM and provenance evaluators by reducing false confidence from template-style inputs

### Notes

- This release focuses on evaluator maturity, stronger proof expectations, and more reliable multi-platform posture assessment
- The trust model continues to distinguish observable signals from evidence-backed proof
- Azure and AWS evaluations are further refined to reduce inflated confidence and better surface cases that still require manual review
- Includes additional advisory profile options for combined GitHub + cloud pipeline scenarios

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v3.0.0

This major release evolves the kit from a clone-only baseline checker into a broader posture evaluation toolkit with report drift analysis, external profile loading, API-backed evidence collection, and a new report JSON contract.

### Highlights

- Expanded the kit beyond clone-only evaluation with API-backed evidence collection workflows
- Introduced report drift analysis to compare evaluation outputs across runs
- Added support for external YAML profile loading and richer profile extensibility
- Upgraded the report JSON contract with new evidence collection metadata
- Improved platform evidence support across GitHub, Azure DevOps, and AWS
- Strengthened human-readable output and diagnostics for operational use

### Improvements

- Better evidence handling through API-backed collection for GitHub, Azure, and AWS
- Improved report transparency with collection method metadata and live collection context
- Stronger extensibility through external profile loading and plugin-based evaluator registration
- Better regression analysis with report comparison and fail-on-regression support
- Improved CLI usability with richer human output, clearer diagnostics, and better profile help guidance
- Stronger validation through packaged report and profile schemas
- Better scaffolded evidence quality through placeholder detection and validation improvements
- Improved terminal behavior and Windows compatibility for human-readable output paths
- Clearer repository detection and stricter evaluation behavior for source inputs
- Promoted multiple controls from experimental to stable while formally deprecating older ones

### Notes

- This is a major release and introduces a new default report JSON contract: `reports/0.2`
- Users with strict downstream integrations depending on the previous JSON shape may need to keep using the older contract explicitly
- The release adds migration-oriented capabilities, including diff-based report comparison and external profile support
- API-backed evidence collection now complements the existing manual evidence model
- Review the migration guidance before upgrading from the 2.x line

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v2.0.1

This patch release stabilizes the 2.0 release path by fixing publication blockers, improving Azure profile recommendation accuracy, and strengthening release validation for package artifacts.

### Highlights

- Fixed the PyPI publish workflow to keep SBOM artifacts separate from distribution packages
- Improved `recommend-profile` detection for Azure repositories using nested pipeline layouts
- Added regression coverage to prevent package artifact mixing and Azure detection regressions
- Updated release-readiness documentation to reflect the corrected publication flow

### Improvements

- Better release reliability by ensuring SBOM output no longer interferes with wheel and sdist publishing
- Improved Azure platform detection for repositories using supported nested pipeline structures
- Stronger regression confidence through dedicated tests for nested Azure pipeline discovery
- Better packaging hygiene through validation that prevents SBOM artifacts from being bundled into distributions again
- Improved operational clarity with updated release-readiness guidance and corrected artifact paths

### Notes

- This is a maintenance-focused patch release in the 2.0.x line
- Focused on publication stability, packaging hygiene, and Azure recommendation accuracy
- No major breaking changes are expected
- Strengthens the release path established in v2.0.0 for safer publication and more predictable platform detection

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v2.0.0

This major release marks the next stage of the project's evolution: from a GitHub-focused local-first policy evaluation kit into a broader multi-platform governance and release-hardening framework for GitHub, Azure DevOps, and AWS.

Built on the foundations established across the 0.x and 1.x lines, v2.0.0 expands platform coverage, strengthens evidence-backed evaluation, improves CLI workflows, and delivers more actionable reporting while preserving the project's local-first trust model.

### Highlights

- Expanded the kit beyond GitHub with maturity and release-hardening ladders for Azure DevOps / Azure Pipelines and AWS CodeBuild / CodePipeline
- Added platform-specific parsers and schema-backed evidence handling for broader governance and pipeline posture evaluation
- Introduced new CLI workflows for profile discovery, batch evaluation, evidence scaffolding, and profile recommendation
- Improved reporting with action insights, prioritization guidance, stronger waiver semantics, and clearer explainability
- Continued the project's progression from initial local policy checks into a more mature operational assessment framework

### Improvements

- Better platform coverage through new GitHub, Azure, and AWS evaluation ladders
- Stronger evaluator maturity with stricter tracks while preserving the `github-level-1` baseline
- Improved CLI usability with `profiles`, `--show-profiles`, `evaluate-many`, `scaffold-evidence`, and `recommend-profile`
- Better automation support through JSON-friendly profile discovery and batch evaluation outputs
- Stronger report quality with root-cause grouping, recommended actions, prioritization sections, and clearer trust-boundary messaging
- Improved evaluator accuracy through tighter disclosure and CodeQL-equivalent heuristics
- Better waiver clarity by distinguishing in-repository versioned waivers from CLI-provided waiver inputs
- Refined documentation, operational guidance, and packaging hygiene for broader adoption and distribution reliability

### Notes

- This is a major release focused on platform expansion, evaluation maturity, and operational usability
- The trust model remains local-first: the kit evaluates what is observable from a repository clone, with optional evidence files for posture that cannot be proven from source alone
- Azure and AWS support in this release are intentionally clone-based and evidence-assisted, not live-tenant verification
- This version builds on the foundations introduced across earlier releases, including packaged policy data, lifecycle-aware controls, schema-backed evidence handling, release hardening, consumer validation flows, and stable 1.x CLI/report contracts
- Human summary output is now more action-oriented, while JSON-oriented automation remains supported

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.3

This patch release improves explainability, evidence validation, consumer-side validation workflows, and packaging hygiene, while preserving the stable 1.0.x contract.

### Highlights

- Improved scorecard explainability across JSON, Markdown, and optional stdout outputs
- Added runtime validation for branch protection evidence against the bundled schema
- Introduced a reproducible consumer smoke workflow for wheel and CLI validation
- Expanded test coverage for adoption paths, evidence handling, and scorecard behavior
- Improved packaging hygiene to avoid unintended bundled artifacts

### Improvements

- Better transparency around whether `--scorecard-json` was loaded and whether it influenced control evaluation
- Stronger evidence trust through schema-based validation of branch protection inputs
- Improved consumer validation with reproducible virtual environment, wheel, and CLI smoke checks
- Better regression confidence through added tests for recommended adoption paths, minimal gap handling, and local branch evidence
- Cleaner packaging behavior by removing recursive data glob side effects and preventing cache artifacts from being bundled
- Refined documentation for official install channels, Windows and PowerShell usage, and packaging operations

### Notes

- This is a maintenance-focused patch release in the 1.0.x line
- No breaking changes are expected for the CLI contract or public report schema
- Focused on explainability, packaging quality, evidence trust, and operational validation confidence
- Continues strengthening the stability and maintainability of the stable 1.0 line

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.2

This patch release improves adoption guidance, regression coverage, CLI summary behavior, and documentation consistency, while preserving the stable 1.0.x contract.

### Highlights

- Added a clearer recommended adoption playbook for practical project rollout
- Improved regression coverage for JSON projection and Markdown summary stability
- Enhanced CLI summary output with better totals and canonical status ordering
- Refined installation guidance, including Windows-friendly execution notes
- Updated cross-links across adoption, maintainer checklists, and examples for a more consistent user path

### Improvements

- Better onboarding support through a more actionable recommended adoption path
- Stronger regression confidence with expanded golden fixtures and report validation tests
- Improved CLI usability with clearer summary output in both human-readable and JSON formats
- Better consistency in report interpretation through stable controls table behavior
- Enhanced documentation alignment across examples, maintainer guidance, and adoption materials
- Improved usability for Windows environments when console scripts are not available on PATH

### Notes

- This is an additive patch release in the 1.0.x line
- No breaking changes are expected for the CLI contract or public report schema
- Focused on adoption clarity, test confidence, and day-to-day usability improvements
- Continues strengthening the stable foundation established in the 1.0 line

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.1

This patch release improves documentation, workflow hygiene, adoption assets, and GitHub Pages presentation, while keeping the project aligned with the 1.0.x stable line.

### Highlights

- Improved maintainer documentation and patch-readiness guidance
- Expanded adoption templates for waivers, views, and workflow integration
- Refined GitHub Actions hygiene with stronger action pinning and workflow consistency
- Improved GitHub Pages presentation for better readability and layout behavior
- Updated repository documentation and validation guidance for smoother project adoption

### Improvements

- Better maintainer support with clearer operational and patch validation guidance
- Improved adoption readiness through additional starter templates and workflow scaffolding
- Stronger CI/CD hygiene with more consistent third-party action pinning practices
- Better alignment between package workflow and security workflow expectations
- Improved GitHub Pages hero layout to avoid visual overlap on larger screens
- Enhanced site readability through softer visual effects and cleaner spacing
- Refined documentation across README, adoption guidance, release readiness, and troubleshooting notes

### Notes

- This is a maintenance-focused patch release in the 1.0.x line
- No major breaking changes are expected
- Focused on documentation quality, workflow hygiene, and presentation improvements
- Continues strengthening repository trust, adoption clarity, and day-to-day maintainability

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v1.0.0

This release marks the first stable major version of the kit, improving workflow organization, packaging alignment, and release maturity while establishing a clearer and more reliable foundation for ongoing evolution.

### Highlights

- First stable major release of the OSS Security Policy as Code Starter Kit
- Improved GitHub Actions structure with clearer CI, security, and deploy workflow separation
- Better packaging alignment for current Python distribution expectations
- Enhanced CLI version visibility and installed package identification
- Refined documentation for release, packaging, contribution, and roadmap guidance

### Improvements

- More organized workflow layout for CI/CD, security checks, and deployment
- Better repository trust posture through stronger action pinning practices
- Improved packaging metadata consistency for release readiness
- Clearer CLI behavior for version reporting and installed package validation
- Enhanced documentation quality across README, contribution flow, and release guidance
- Stronger foundation for stable public usage and future versioned evolution

### Notes

- This is the first stable major release in the 1.x line
- Focused on stability, release maturity, and maintainability
- No major breaking changes are expected for normal CLI usage
- PyPI publishing may still require manual steps unless trusted publishing is configured
- Some schema references may continue to reflect the evaluation output contract version rather than the Python package version

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.4.0

This release improves policy data maturity, strengthens evidence validation, and expands release integrity signals with SBOM, build provenance, and broader CI coverage.

### Highlights

- Added lifecycle metadata to controls for clearer policy maturity tracking
- Introduced new experimental controls for dependency scanning and SBOM generation
- Strengthened branch protection evidence validation with a more explicit trust model
- Improved package workflow with SBOM generation and signed build provenance
- Expanded CI coverage across Ubuntu, macOS, and Windows
- Added coverage reporting to improve test visibility in CI

### Improvements

- Better control maturity visibility across JSON and Markdown reports
- Improved schema enforcement for policy data consistency
- Stronger evidence handling for branch protection validation
- Enhanced release integrity with CycloneDX SBOM generation
- Improved supply chain trust signals through build provenance attestation
- Better cross-platform confidence with multi-OS quality validation
- Increased test observability through CI coverage reporting

### Notes

- This release focuses on policy lifecycle clarity, stronger evidence validation, and release trust
- The new controls are currently experimental and should be treated as advisory until they mature
- JSON reports generated by v0.3.x are not compatible with the v0.4.0 schema because `lifecycle` is now required in `control_result`
- Re-generate reports with v0.4.0 to align with the updated schema

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.3.0

This release strengthens packaging, CLI usability, CI reliability, and release governance, making the kit easier to distribute, validate, and operate with clearer automation behavior.

### Highlights

- Improved package and release workflow for more reliable distribution
- Expanded CLI behavior with clearer output and exit-code handling
- Stronger report validation and test coverage for release confidence
- Better release-readiness guidance and repository governance documentation
- More consistent CI decisions for automation and publishing workflows

### Improvements

- Added package CI workflow with build, validation, and install checks
- Improved maintainers' ability to validate distribution artifacts before publishing
- Enhanced CLI usability with new output and summary options
- Clearer pass/fail automation through documented exit-code behavior
- Stronger report validation against the project schema
- Improved test coverage for JSON, Markdown, and failure-path scenarios
- Better documentation for release readiness, required checks, and maintainer workflows

### Notes

- This release focuses on packaging maturity, CLI clarity, and release engineering quality
- No major breaking changes are expected in the core evaluation model
- Strengthens the project for safer publishing and more predictable CI/CD usage
- Continues improving maintainability, trust, and automation confidence across the repository

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.2.0

This release improves package structure, installation readiness, and test organization, making the kit cleaner to consume, easier to maintain, and more aligned with a distributable Python package model.

### Highlights

- Reorganized the project into a more installable package-oriented layout
- Moved policy profiles and controls into package data for cleaner distribution
- Restructured the test suite by layers with better repository-based fixtures
- Removed duplicated root-level artifacts to improve maintainability
- Updated CI, contribution guidance, and architecture/adoption documentation to match the new model

### Improvements

- Better packaging consistency for local installation and distribution workflows
- Improved maintainability through a cleaner repository structure
- More reliable test organization with clearer separation of application, infrastructure, CLI, and adapter layers
- Stronger fixture strategy for workflow and parsing validation scenarios
- Better alignment between documentation, repository layout, and actual project usage

### Notes

- This release focuses on structural maturity, packaging hygiene, and maintainability
- No major conceptual change to the CLI behavior or control scope
- Users consuming root-level `controls/` and `profiles/` should now use the packaged artifacts under `src/oss_policy_kit/data/`
- Continues the same local-first assessment philosophy established in v0.1.0

**License:** Apache-2.0.

---

## OSS Security Policy as Code Starter Kit v0.1.0

This first publishable release delivers a local-first starter kit for evaluating OSS governance signals, GitHub Actions hygiene, and release readiness, with structured reports and explicit boundaries about what automation can and cannot verify.

### Highlights

- Local CLI to evaluate repositories directly from disk
- Versioned policy profiles with Markdown and JSON reporting
- Initial control catalog covering governance files, workflow hygiene, permissions, and release readiness signals
- Example vulnerable and hardened repositories for validation and learning
- Waiver format with schema validation, tests, and security-focused CI workflows
- Honest evidence model that clearly distinguishes automated findings from manual-review-required items

### Improvements

- Better structure for OSS governance and policy-as-code evaluation
- Clearer reporting outputs for local review and decision-making
- Stronger baseline for GitHub Actions security hygiene assessments
- Improved consistency across controls, examples, waivers, and CLI workflows
- More transparent handling of checks that require platform-side verification or human validation

### Notes

- This is the first publishable baseline of the kit
- Focused on local assessment, governance visibility, and release readiness support
- Does not replace GitHub platform configuration review, threat modeling, or formal OpenSSF certification processes
- Several controls intentionally remain manual-review-required when evidence cannot be proven locally

**License:** Apache-2.0.
