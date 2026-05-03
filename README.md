# OSS Security Policy as Code Starter Kit

Evaluate clone-visible OSS repository governance plus GitHub Actions, Azure Pipelines, and AWS CodeBuild/CodePipeline signals from a local clone. Platform truth outside the repository still requires evidence or manual review.

This project is intentionally small and explicit about trust boundaries. GitHub support is the most mature path today; Azure and AWS support are clone-based and evidence-driven rather than live platform verification.

## Quick Links

- [What This Kit Does](#what-this-kit-does)
- [Current Release State](#current-release-state)
- [Quickstart](#quickstart)
- [CI/CD Integration](#ci-cd-integration)
- [Validation Walkthrough](#validation-walkthrough)
- [CLI Usage](#cli-usage)
- [How To Interpret Results](#how-to-interpret-results)
- [Adoption Paths](#adoption-paths)
- [Bundled profiles overview](docs/profiles/overview.md)
- [Release hard-gate playbook](docs/release-playbook-hardgate.md)
- [Release-hardening workflow (L3 + evidence)](docs/release-hardening-workflow.md)
- [Public release gate](docs/public-release-readiness.md)
- [Documentation](#documentation)
- [Maintainer Self-Check](#maintainer-self-check)

## At A Glance

| Area | What you get |
| --- | --- |
| Current release | `v4.0.2` / Python package `oss-policy-kit==4.0.2` |
| Input | A local repository clone |
| Output | `evaluation-report.json` and `evaluation-report.md` |
| Core scope | Clone-visible governance and GitHub/Azure/AWS CI/CD signals |
| Profiles | `github-*`, `azure-*`, and `aws-*` ladders (`level-1..3`, `release-hardening-*`) via `profiles` or `--show-profiles`; optional bundled **`github-aws-level-2`** / **`github-azure-level-2`** combine GitHub workflow signals with AWS or Azure CI signals (advisory) |
| Exceptions | Waiver registry support with owner, reason, and expiry |
| Examples | Hardened and vulnerable sample repositories |
| Packaging | Python package with CLI and bundled policy data |
| Positioning | Evidence and signals, not certification |
| **Assurance model** | Each catalog control is labeled **`deterministic`**, **`signal`**, or **`evidence-backed`**; the value is copied into **`reports/0.3`** JSON and Markdown rows so consumers can reason about proof strength ( **`reports/0.3`** adds **`summary_by_gate_role`** for `--fail-on` semantics — see `docs/reports-contract-v0.3.md`; use **`--report-json-contract 0.2`** for the previous wire shape). |
| **Profiles CLI (`profiles --format json`)** | **`profile-list/v2`** adds **`family`**, **`posture`**, **`live_signal_posture`**, plus **`maturity_label`**, **`assurance_mix`**, **`is_legacy_alias`**, **`canonical_profile_id`**. Discovery flags **`--family`**, **`--only-extreme`**, **`--advisory-only`** narrow the listing. **`github-release-hardening`** remains a **legacy** alias of **`github-release-hardening-1`**. **`summary_by_status.fail == 0` is not “all-pass”** — see [docs/profiles/overview.md](docs/profiles/overview.md) and [docs/release-playbook-hardgate.md](docs/release-playbook-hardgate.md). |

## Current Release State

`v4.0.2` is the current public-launch release line. It is a documentation, release-hygiene, and CI-hygiene patch on top of the immutable `v4.0.1` tag and does not change runtime behavior, bundled profiles, the control catalog, evaluator logic, CLI flags, report schemas, or packaged policy data.

| Surface | Current state |
| --- | --- |
| Package | `oss-policy-kit==4.0.2` is the package version for this release line |
| GitHub Release | `v4.0.2` is the release target for wheel and sdist assets; `v4.0.1` remains available as an immutable predecessor |
| Default branch | `master`; it may contain documentation, site, or CI hygiene commits after the immutable `v4.0.2` tag |
| License | Apache-2.0 (`LICENSE` + `NOTICE`) |
| Report contract | `reports/0.3` by default; `0.2` and `0.1` remain selectable for compatibility |
| Security workflow | Scanners run in `Security CI/CD`; SARIF upload is gated by `ENABLE_CODE_SCANNING_UPLOAD=true` so validation does not fail when Code Scanning upload APIs are unavailable |
| Public scope | Source, policy data, docs, examples, templates, tests, screenshots, and optional GitHub Pages site |
| Non-public local state | Assistant notes, private planning, generated reports, build outputs, caches, local secrets, and maintainer scratch files are ignored and must not be published |

The repository is designed to be reproducible from a clean clone: install the package, run the built-in examples, and compare the generated JSON/Markdown reports. Public release readiness evidence is documented under `docs/`, especially [public release readiness](docs/public-release-readiness.md), [public launch checklist](docs/public-launch-checklist.md), and [publication traceability matrix](docs/publication-traceability-matrix.md).

## Why This Exists

Many OSS baselines mix three very different things:

- controls that can be checked from a clone
- controls that require platform context
- controls that still require human judgment

This kit keeps those categories separate.

Instead of collapsing everything into a misleading score, it gives you:

- versioned controls
- staged profiles
- explicit result states
- local JSON and Markdown reports
- waiver support
- reproducible examples and templates

## What This Kit Does

The starter kit helps you assess whether a repository shows a practical OSS baseline in files and workflows that are observable locally.

It focuses on:

- `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `CODEOWNERS`, changelog presence
- clone-visible GitHub Actions, Azure Pipelines, and AWS build/pipeline structure and hygiene signals
- report generation for humans and pipelines
- policy lifecycle markers such as `stable`, `experimental`, and `deprecated`
- additive local evidence such as waivers and optional platform evidence files

## What This Kit Does Not Do

- It is not a universal application security scanner.
- It is not an OSPS certification engine.
- It is not a compliance guarantee.
- It is not a substitute for threat modeling, secure code review, pentesting, or GitHub settings review.
- It does **not** replace dedicated SAST, DAST, or deep SCA products; it complements them by checking governance and clone-visible CI hygiene.
- Similar-looking results across unrelated repositories are normal when those repos lack visible governance and CI signals in the clone; that reflects scope, not a broken engine.

Treat outputs as local evidence and prioritization signals, not as "pass means safe".

## Who It Is For

- OSS maintainers who want a practical baseline
- AppSec and DevSecOps engineers supporting open source programs
- teams building a demonstrable policy-as-code starter project

## Quickstart

Requires Python 3.12+.

### How to install (official channels)

Pick one path; they are listed in priority order for most users.

1. **From PyPI (recommended for most consumers)**  
   Install the latest published release:

   ```bash
   python -m pip install oss-policy-kit
   ```

   Install a specific released version:

   ```bash
   python -m pip install oss-policy-kit==4.0.2
   ```

   Quick sanity check:

   ```bash
   python -m oss_policy_kit --version
   ```

2. **From GitHub Release artifacts (wheel or sdist)**  
   Download `oss_policy_kit-*.whl` or `oss_policy_kit-*.tar.gz` from the
   [Releases](https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit/releases)
   page, then install in a clean virtual environment:

   ```bash
   python -m pip install /path/to/oss_policy_kit-<version>-py3-none-any.whl
   ```

   On Windows PowerShell, after `python -m build`, a typical install from the repo root is:

   ```powershell
   python -m pip install (Get-ChildItem dist\oss_policy_kit-*.whl | Select-Object -First 1 -ExpandProperty FullName)
   ```

   Prefer **`python -m oss_policy_kit`** for CLI entry on Windows so you do not depend on `Scripts\` being on `PATH`.

3. **From source (contributors and local development)**  
   Clone the repository and use an editable install with dev tools:

   ```bash
   python -m pip install -e ".[dev]"
   ```

### Install From The Repository (development)

```bash
python -m pip install -e ".[dev]"
```

### Run The Built-In Examples

```bash
python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

### Read The Outputs

- `evaluation-report.md` for human review
- `evaluation-report.json` for tooling, CI, and regression checks

### What Success Usually Looks Like

- `examples/hardened-repo` on `github-level-1`: `pass: 14` (all active controls in the profile)
- `examples/vulnerable-repo` on `github-level-1`: multiple `fail`
- this repository on `github-level-1`: use the current self-check report as the source of truth; do not assume `all-pass` on every revision
- `github-release-hardening-1`: typically `pass` plus one branch-protection result that remains `manual-review-required` or `self-attested`, depending on local evidence

## CI/CD Integration

Starter workflows live under [`templates/workflows/`](./templates/workflows/):

- [`github-oss-policy-check.yml`](./templates/workflows/github-oss-policy-check.yml) — baseline `evaluate` against `github-level-1`, fail the job when any control is `fail`.
- [`github-oss-policy-check-with-waivers.yml`](./templates/workflows/github-oss-policy-check-with-waivers.yml) — same as above but passes `--waivers ./waivers/waivers.yaml`.
- [`github-oss-policy-check-level-2.yml`](./templates/workflows/github-oss-policy-check-level-2.yml) — stricter `github-level-2` profile when your GitHub Actions maturity justifies it.

Typical CI command:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --fail-on fail --output-dir ./oss-policy-reports
```

Interpret **exit codes** in pipelines: **`0`** means evaluation finished and the `--fail-on` threshold was not violated; **`1`** means the gate tripped (`fail` counts, or `manual-review-required` when using `--fail-on degraded`). **`2`** is usage or load errors—treat as a pipeline configuration problem, not a policy failure.

Artifacts in the workflow templates upload `./oss-policy-reports/` so you retain JSON and Markdown evidence even when the gate fails early.

GitHub Releases for this kit include **wheel** and **sdist** distribution assets. The publish workflow also generates a CycloneDX SBOM as a CI artifact for release evidence.

## Validation Walkthrough

This section is the fastest way to understand how the kit is meant to be used in practice. It walks through the command flow in the same order a maintainer or AppSec engineer would normally follow:

1. learn the CLI surface
2. choose the right profile
3. run a quick demo or self-check
4. compare expected good and bad repository shapes
5. turn the same evaluation into a CI gate

Treat these artifacts as operational evidence. They show that the kit runs, reports clearly, and differentiates repository posture. They do **not** claim that a `pass` result is equivalent to universal security assurance.

### Command Flow At A Glance

| Step | Command or artifact | Use it when |
| --- | --- | --- |
| Understand the CLI | `python -m oss_policy_kit --help` | You want to see the supported commands, flags, and exit codes before wiring the tool into scripts or CI. |
| Discover profiles | `python -m oss_policy_kit profiles` or `python -m oss_policy_kit --show-profiles` | You need to choose the right platform and strictness level before running an evaluation. |
| Compare baseline outcomes | `python -m oss_policy_kit evaluate --target ./examples/... --summary-only` | You want a fast visual contrast between a stronger fixture and a weaker fixture under the same profile. |
| Self-check the current repo | `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck` | You want to validate the current repository revision using the same kit it ships. |
| Compare fixtures | `python -m oss_policy_kit evaluate --target ./examples/...` | You want a stable passing fixture and a stable failing fixture for demos, tests, or onboarding. |
| Gate CI | `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-ci --fail-on fail` | You want reports written first and the pipeline blocked only when the chosen threshold is violated. |

### 1. Learn The CLI Surface

Start with the help output. This is the right command to use when you are integrating the tool for the first time, because it shows:

- the preferred `evaluate` entrypoint
- compatibility invocation forms
- output options such as `--summary-only` and `--format`
- the exit-code contract used by local scripts and CI

```bash
python -m oss_policy_kit --help
```

<p align="center">
  <img src="./screenshots/01-cli-help.png" alt="OSS Policy Kit CLI help showing usage, evaluate subcommand, options, and exit codes." width="960">
</p>

### 2. Discover And Choose A Profile

Before evaluating a repository, choose the profile that matches the platform and the desired assurance level. That is the context for the two profile-discovery commands:

- `python -m oss_policy_kit --show-profiles` prints the bundled profile table
- `python -m oss_policy_kit profiles` prints the same bundled profile table

Use `level-1` when you are starting with the baseline and want honest clone-only checks. Move to higher levels or `release-hardening-*` profiles when you want stricter controls and are ready to provide supporting evidence for release posture.

```bash
python -m oss_policy_kit --show-profiles
python -m oss_policy_kit profiles
```

<p align="center">
  <img src="./screenshots/02-cli-show-profiles.png" alt="Built-in profile table showing profile id, title, platform, level, audience, and description." width="960">
</p>

<p align="center">
  <img src="./screenshots/02-cli-profiles.png" alt="Compact bundled profile listing showing GitHub, Azure, and AWS ladders plus the legacy github-release-hardening alias." width="960">
</p>

### 3. Compare Hardened And Vulnerable Baselines

When you want the fastest practical explanation of what the kit does, compare the bundled hardened and vulnerable fixtures under the same `github-level-1` profile. This keeps the policy set constant and changes only the repository posture, so the contrast is easy to explain.

The first command in the screen targets `./examples/hardened-repo` and uses `--summary-only` to collapse the result to status counts instead of printing file paths and report locations. In the current fixture, `pass=14` means all active controls in `github-level-1` passed for the hardened repository.

The second command targets `./examples/vulnerable-repo` with the same profile and the same summary mode. `pass=2 | fail=11 | manual-review-required=1` means the kit found only two passing controls, eleven direct failures, and one control that cannot be cleanly confirmed from the clone alone. `controls: 14` in both blocks confirms that the same policy set was evaluated in both cases, so the difference comes from repository posture, not from a different rule set.

Use this comparison when you want a compact, high-signal explanation of the product: the hardened fixture shows the target baseline outcome, and the vulnerable fixture shows that missing governance and CI/CD hygiene signals really do degrade the result.

<p align="center">
  <img src="./screenshots/03-demo-contrast.png" alt="Terminal screenshot showing the hardened example returning pass=14 and the vulnerable example returning pass=2, fail=11, and manual-review-required=1." width="960">
</p>

### 4. Validate The Package And The Current Repository

After the CLI and profiles are clear, the next step is to validate that the package itself is healthy and that the current repository revision can evaluate cleanly.

Run the automated test suite when you want regression confidence before changing code, policy data, or templates:

```bash
python -m pytest -q
```

The passing test run below is evidence that the implementation is stable at the code level, not just at the documentation level.

<p align="center">
  <img src="./screenshots/03-test-suite.png" alt="Pytest output showing the automated test suite passing with 408 passed and 1 skipped." width="960">
</p>

Then run a maintainer self-check when you want to know whether the repository itself satisfies the chosen baseline in its current revision:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck
```

This is the command to use when validating the repository before release, before documentation updates, or after changing workflows and governance files. The current repository revision produces `pass=14` on `github-level-1`; generated reports under `./out/selfcheck` remain the source of truth for the exact commit being evaluated.

<p align="center">
  <img src="./screenshots/04-selfcheck-current.png" alt="Current repository self-check report for github-level-1." width="960">
</p>

### 5. Compare Known-Good And Known-Bad Fixtures

The bundled example repositories are the clearest way to understand what the tool is checking and why those checks matter.

Use the hardened example when you want to show the target baseline outcome:

```bash
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

This repository includes the expected governance files and CI signals, so it is the reference fixture for a strong `github-level-1` result.

<p align="center">
  <img src="./screenshots/05-example-hardened.png" alt="Hardened example report showing pass=14 on github-level-1." width="960">
</p>

Use the vulnerable example when you want to prove that the kit is not a cosmetic report generator and that obvious repository weaknesses really do surface as non-pass states:

```bash
python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
```

This is the right fixture for onboarding, demos, and CI-gate demonstrations because it shows missing governance artifacts, weak workflow patterns, and other expected gaps as actionable failures.

<p align="center">
  <img src="./screenshots/06-example-vulnerable.png" alt="Vulnerable example report showing pass=2, fail=11, and manual-review-required=1 on github-level-1." width="960">
</p>

### 6. Read The Controls Table And Detail Blocks

After you see a fixture pass or fail at the summary level, the next step is to inspect the generated Markdown report and understand why each control resolved that way.

Use the vulnerable fixture for this walkthrough because it produces a mix of governance, CI/CD, release, and supply-chain findings:

```bash
python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable
```

Open `./out/vulnerable/evaluation-report.md` and scroll past the summary sections. The `## Controls` table is the compact triage view: one row per control, with the control id, category, lifecycle, status, confidence, short reason, remediation hint, and waiver column.

<p align="center">
  <img src="./screenshots/08-controls-table.png" alt="Controls table from the vulnerable example report showing control ids, status, confidence, reason, remediation, and waiver columns." width="960">
</p>

That table answers the first-level questions quickly: what failed, how confident the kit is, and what should be fixed next. In this example, the governance controls fail because the repository is missing `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, and `LICENSE`, while `CI-WF-005` passes because a workflow file is present. The same table also shows why `GOV-WAIV-014` reads as **`manual-review-required`** when no versioned in-repo waiver policy file is present: a CLI waiver file is not the same thing as a versioned in-repo waiver policy.

When you need the full reasoning behind one result, keep scrolling into `## Detail`. Each control expands into a dedicated block with status, lifecycle, confidence, reason, remediation, and evidence when the evaluator found a concrete file or signal.

<p align="center">
  <img src="./screenshots/09-control-details.png" alt="Detailed control blocks from the vulnerable example report showing fail and pass results with reasons, remediation, and evidence." width="960">
</p>

That detailed view is what makes the report actionable. A failing control explains exactly what is missing, while a passing control explains which signal satisfied the rule. In this example, governance controls fail because required repository files are absent, and `CI-WF-005` passes because the evaluator detected at least one GitHub Actions workflow. This is the section to use when you are deciding what to remediate first or when you need to justify a result to someone else reviewing the repository.

### 7. Turn Evaluation Into A CI Gate

Once the report content makes sense locally, the same evaluation can be used as a pipeline gate. The key flag is `--fail-on`, which turns result thresholds into exit-code policy:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-ci --fail-on fail
```

`--fail-on` modes:

- `none`: never fail from result statuses (exit `0` unless internal/usage errors).
- `fail`: exit `1` if any control has status `fail`.
- `degraded`: exit `1` if any control has `fail` **or** `manual-review-required`.
- Operational warnings alone do **not** trigger `fail` or `degraded`.

Use this mode when you want the job to:

1. complete evaluation
2. write `evaluation-report.json` and `evaluation-report.md`
3. fail the CI step only after the evidence is available for review

That behavior matters. A blocked pipeline should still leave behind actionable evidence. The screenshots below are sanitized real CI runs that show both outcomes: a passing GitHub self-check against the current repository shape, a failing GitHub gate against the intentionally vulnerable fixture, and the same failure pattern in Azure Pipelines on an Ubuntu/Linux agent.

<p align="center">
  <img src="./screenshots/10-github-actions-selfcheck-pass.png" alt="GitHub Actions self-check pass demo for github-level-1 showing pass=14." width="960">
</p>

<p align="center">
  <img src="./screenshots/11-github-actions-selfcheck-fail.png" alt="GitHub Actions self-check fail demo for github-level-1 against the vulnerable fixture showing fail=11, manual-review-required=1, and exit code 1." width="960">
</p>

Keep the output directory as a published pipeline artifact so reviewers can inspect the JSON and Markdown reports even when `--fail-on fail` blocks the job. The Azure example is a failure-path demo against a minimal target; it is not a status claim for the current repository revision.

<p align="center">
  <img src="./screenshots/12-azure-pipelines-selfcheck-fail.png" alt="Sanitized Azure Pipelines Ubuntu agent step showing azure-level-1 reports written before Bash exits with code 1 under fail-on fail." width="960">
</p>

## CLI Usage

### Public Contract

The supported CLI forms are:

- preferred: `python -m oss_policy_kit evaluate ...`
- compatible: `python -m oss_policy_kit --target ./repo --profile ...`
- also supported: `python -m oss_policy_kit ./repo --profile ...`

The explicit `evaluate` subcommand is the clearest form and should be preferred in docs, scripts, and examples.

### Day-to-day usage

1. **First run**: install the package, then `python -m oss_policy_kit profiles` (or `--show-profiles`) to pick a ladder, and `python -m oss_policy_kit recommend-profile --target .` for a quick hint.
2. **Local maintainer loop**: `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/latest` before tagging or opening a release PR; open `evaluation-report.md` for the narrative view.
3. **Multi-app / monorepo**: `python -m oss_policy_kit evaluate-many --target-root ./apps --profiles github-level-1 --output-dir ./out/batch` — read `evaluation-batch.md` first (consolidated totals, repeated gaps, relative paths to per-repo reports).
4. **Waivers**: keep versioned waivers in-repo for `GOV-WAIV-014`; use `--waivers path.yaml` only for temporary or CI-local exceptions and treat them as explicitly out-of-band from versioned policy.
5. **Release-hardening + evidence**: run `scaffold-evidence` once, fill `.oss-policy-kit/evidence/*.json`, then evaluate with `github-release-hardening-*` (or Azure/AWS equivalents). Re-run scaffold **without** `--force` to preserve hand-edited JSON; use `--force` only when you intend to replace templates.
6. **Interpreting scope**: read [What This Kit Does](#what-this-kit-does) / [What This Kit Does Not Do](#what-this-kit-does-not-do) when results look similar across apps — the kit measures clone-visible posture, not application logic flaws.

### Profile Discovery

Use either of these:

- `python -m oss_policy_kit profiles`
- `python -m oss_policy_kit --show-profiles`

Both commands list the bundled ladders with platform, level, control count, and whether the profile stays clone-only or extends into release-hardening/evidence expectations. **Listing goes to stdout** (errors stay on stderr). Machine-readable catalog:

```bash
python -m oss_policy_kit profiles --format json
```

Heuristic profile suggestion from repository layout:

```bash
python -m oss_policy_kit recommend-profile --target ./examples/hardened-repo
python -m oss_policy_kit recommend-profile --target . --format json
```

`recommend-profile` is **heuristic guidance**, not a compliance verdict. It can be strongly influenced by local `.oss-policy-kit/evidence/*.json`, platform signals in CI files, and repository manifests/lockfiles. Treat the recommendation as a starting point, then confirm with an explicit `evaluate` run and review the resulting statuses.

### Batch / Monorepo

Evaluate each **immediate child directory** of a root folder against one or more profiles (paths with spaces are supported via normal shell quoting):

```bash
python -m oss_policy_kit evaluate-many --target-root ./path/to/apps --profiles github-level-1 --output-dir ./out/batch
```

This writes per-target reports under `./out/batch/<child-name>/<profile-id>/` plus consolidated `evaluation-batch.json` and `evaluation-batch.md`.

`evaluate-many` inspects immediate child directories of `--target-root`. It does not recurse into monorepos. For nested layouts, run `evaluate-many` once per level or invoke `evaluate` per target.

### Evidence Scaffolding

Generate schema-shaped starter files under `.oss-policy-kit/evidence/`:

```bash
python -m oss_policy_kit scaffold-evidence --target . --platform github
```

By default, **existing files are not overwritten** (stdout prints `created` / `skipped` / `overwritten`). Use `--force` only when you want to replace templates you have already edited.

Replace placeholders, then re-run `evaluate` with a `release-hardening-*` profile. Evidence remains **self-attested** (maintainer-supplied), not platform-verified.

### Common Examples

Subcommand with `--target`:

```bash
python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

Subcommand with positional target:

```bash
python -m oss_policy_kit evaluate ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened
```

Top-level compatibility form:

```bash
python -m oss_policy_kit --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened-root
```

### Optional Inputs

Unix-like shells:

```bash
python -m oss_policy_kit evaluate --target ./path/to/repo \
  --profile github-level-1 \
  --output-dir ./out \
  --waivers ./waivers/waivers.example.yaml \
  --scorecard-json ./path/to/scorecard.json
```

Windows PowerShell:

```powershell
python -m oss_policy_kit evaluate --target .\path\to\repo --profile github-level-1 --output-dir .\out --waivers .\waivers\waivers.example.yaml
```

### Pipeline-Friendly Output

For compact stdout suitable for CI parsing:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out --summary-only --format json
```

The JSON summary includes:

- ordered `summary_by_status`
- `controls_total`
- `operational_warnings_count`

The **human** `--summary-only` mode prints a short, action-oriented recap (counts, top gaps, suggested next step) while keeping this JSON contract stable.

### Waivers: versioned in repo vs `--waivers`

- **`--waivers`**: external YAML loaded for **this run only**; may set specific controls to `waived`. The report states the absolute path under `external_waiver_path`.
- **`GOV-WAIV-014`**: checks for a **versioned** waiver policy file **inside the clone** (for example `waivers/waivers.yaml`). Using `--waivers` does **not** satisfy that control by design; the Markdown report explains both mechanisms side by side.

### Exit Codes

After a successful evaluation:

| Code | Meaning |
| --- | --- |
| `0` | Completed and `--fail-on` threshold was not violated |
| `1` | Completed and `--fail-on` threshold was violated |
| `2` | Invalid usage, missing paths, or other user-correctable errors |
| `3` | Unexpected internal error |

### Windows Note

`pyproject.toml` exposes the `oss-policy-kit` console script, but on Windows the Scripts directory is not always on `PATH`.

- canonical invocation: `python -m oss_policy_kit`
- if you prefer the console script, use an activated virtual environment or ensure the Scripts directory is on `PATH`

## Profiles

Bundled profiles are easier to inspect from the CLI than from a static README table:

```bash
python -m oss_policy_kit profiles
python -m oss_policy_kit --show-profiles
```

Profile families included in this build:

| Family | Levels | Purpose |
| --- | --- | --- |
| `github-*` | `level-1..3`, `release-hardening*` | Most mature path; GitHub workflow posture plus optional platform evidence |
| `azure-*` | `level-1..3`, `release-hardening-1..3` | Azure Repos / Azure Pipelines clone-based checks plus optional evidence |
| `aws-*` | `level-1..3`, `release-hardening-1..3` | AWS CodeBuild / CodePipeline clone-based checks plus optional evidence |

### Ladder model (L1 starter, L2 advisory, L3 extreme)

Each platform family follows the same ladder: **L1** is the starter baseline (daily PRs, clone-visible checks), **L2** is the advisory scorecard (trunk/merge visibility, never a release gate), and **L3** is the extreme hard-gate (release or pre-release tag, evidence-backed). The matching `release-hardening-{1,2,3}` tier layers release-time evidence expectations on top of the same posture. Use the table below to pick the profile per CI moment; `--fail-on` semantics follow the **Recommended gate** column rendered by `python -m oss_policy_kit profiles --format compact`.

| Profile                         | Use case                                            | Recommended CI gate                       | Depends on evidence? |
|---------------------------------|-----------------------------------------------------|-------------------------------------------|----------------------|
| `github-level-1`                | OSS starter baseline, onboarding                    | `--fail-on fail` on PR                    | No                   |
| `github-level-2`                | Biweekly GitHub maturity scorecard                  | Advisory (`--fail-on none`)               | No                   |
| `github-level-3`                | Strict GitHub release gate                          | `--fail-on fail` on release branch        | **Yes** — `.oss-policy-kit/evidence/github-*.json` |
| `github-release-hardening-1`    | Light GitHub release gate                           | `--fail-on fail` on release tag           | Nearly none (1 evi)  |
| `github-release-hardening-2`    | GitHub release gate with evidence                   | `--fail-on fail` on release tag           | **Yes**              |
| `github-release-hardening-3`    | Hard GitHub release gate                            | `--fail-on fail` on release tag           | **Yes** — GitHub evidence + release artifacts |
| `github-release-hardening`      | **Legacy alias** of `github-release-hardening-1`    | Migrate to the canonical id               | —                    |
| `github-aws-level-2`            | Hybrid advisory — GitHub SCM + AWS CI               | Advisory-only                             | No                   |
| `github-azure-level-2`          | Hybrid advisory — GitHub SCM + Azure CI             | Advisory-only                             | Partial (1 Azure evi) |
| `aws-level-1`                   | AWS CodeBuild/CodePipeline starter                  | `--fail-on fail` on PR                    | No                   |
| `aws-level-2`                   | AWS scorecard                                       | Advisory                                  | No                   |
| `aws-level-3`                   | Strict AWS release gate                             | `--fail-on fail` on release               | **Yes** — `.oss-policy-kit/evidence/aws-*.json` |
| `aws-release-hardening-1`       | Light AWS release gate                              | `--fail-on fail` on release tag           | Partial (2 evi)      |
| `aws-release-hardening-2`       | AWS release gate with evidence                      | `--fail-on fail` on release tag           | **Yes**              |
| `aws-release-hardening-3`       | Hard AWS release gate                               | `--fail-on fail` on release tag           | **Yes** — full AWS evidence |
| `azure-level-1`                 | Azure Pipelines starter                             | `--fail-on fail` on PR                    | No                   |
| `azure-level-2`                 | Azure scorecard                                     | Advisory                                  | Partial (1 evi)      |
| `azure-level-3`                 | Strict Azure release gate                           | `--fail-on fail` on release               | **Yes** — `.oss-policy-kit/evidence/azure-*.json` |
| `azure-release-hardening-1`     | Light Azure release gate                            | `--fail-on fail` on release tag           | Partial (2 evi)      |
| `azure-release-hardening-2`     | Azure release gate with evidence                    | `--fail-on fail` on release tag           | **Yes**              |
| `azure-release-hardening-3`     | Hard Azure release gate                             | `--fail-on fail` on release tag           | **Yes** — full Azure evidence |

For the end-to-end evidence workflow that L3 and release-hardening-3 expect, see [docs/release-hardening-workflow.md](docs/release-hardening-workflow.md).

> **Maturity stance (honest):** inside this kit the **GitHub family is the most mature path**,
> because `github-level-3` / `github-release-hardening-3` combine deterministic workflow parsing
> with evidence-backed branch-protection and environment controls. The **Azure** and **AWS**
> hard-gate families (`*-level-3`, `*-release-hardening-3`) are the strictest bundled gates for
> their platforms but still rely more on evidence discipline than on deterministic parsing, so
> treat them as close — not equal — to the GitHub hard-gate family until Azure/AWS collectors
> reach parity. The hybrid profiles (`github-azure-level-2`, `github-aws-level-2`) are
> **advisory-only** and must not be used as release gates.

> **Canonical vs legacy release-hardening id:** use **`github-release-hardening-1`** in
> documentation, UX, and CI gates. The legacy id **`github-release-hardening`** is kept only
> as a backwards-compatibility alias when consumers reference the filesystem path of the
> legacy profile YAML. New adopters should always cite `github-release-hardening-1`.

### AWS profile ladder (`aws-*`)

- **Starter** (`aws-level-1`, `aws-release-hardening-1`): honest clone checks; scanner/SBOM/provenance items are **signal** controls (PASS is directional, see `confidence` and catalog `assurance`).
- **Advisory** (`aws-level-2`, `aws-release-hardening-2`): adds a **structured** CodePipeline export under `pipelines/aws/` and stricter managed-secret rules in buildspec; still uses **signal** controls for tool mentions in YAML.
- **Hard-gate** (`aws-level-3`, `aws-release-hardening-3`): **deterministic** + **evidence-backed** controls (pipeline/build posture, IAM/identity, artifact-bound SBOM/provenance JSON, evidence freshness). `aws-release-hardening-3` layers the advisory signal bundle on top for release visibility.

> **`AWS-CC-046` (CodeCommit review posture) is intentionally optional** and is **not** bundled into
> any default AWS profile (including `aws-level-3` / `aws-release-hardening-3`). AWS CodeCommit is
> not the default SCM for most users of this kit, and bundling a CodeCommit-specific control would
> silently penalise teams that use GitHub or Azure Repos as their SCM. Enable `AWS-CC-046` only by
> composing it explicitly — via a custom profile or a dedicated evidence file — when CodeCommit is
> the actual source of truth for your repositories. This keeps the default AWS gate honest about
> what it actually verifies.

**Manual evidence vs `collect-evidence`**: self-filled JSON under `.oss-policy-kit/evidence/` is evaluated as **self-attested** unless `attested_by` / `collection` metadata shows **live** API collection, in which case some AWS controls can reach **`pass`** with higher confidence.

### Azure profile ladder (`azure-*`)

- **Starter** (`azure-level-1`, `azure-release-hardening-1`): clone-visible governance plus **AZ-PIPE-027..029** and the **signal** bundle **AZ-SEC/SBOM/SCA-031..033** (directional PASS, see catalog **`assurance: signal`**). **`azure-release-hardening-1`** adds **AZ-PLAT-034** / **AZ-PLAT-035** evidence expectations on top of that starter set.
- **Advisory** (`azure-level-2`, `azure-release-hardening-2`): adds **AZ-PIPE-030** (secure template `extends`) and **AZ-IDENT-036** (YAML deployment signals when governance JSON is absent; governance path when present). **`azure-release-hardening-2`** layers **AZ-PLAT-034/035** like rh-1.
- **Hard-gate** (`azure-level-3`): **deterministic** pipeline presence, **GOV-EVIDFRESH-054**, evidence-backed **AZ-PLAT-034/035**, **AZ-SCONN-056**, **AZ-WIFEV-057**, **AZ-IDENT-036**, and artifact-bound **AZ-ARTSBOM-058** / **AZ-ARTPRV-059**. Scanner/SBOM/SCA **031..033** are **not** in this profile so a “green” hard gate cannot rest on weak YAML mentions alone.
- **`azure-release-hardening-3`**: same hard-gate core as **`azure-level-3`** **plus** the **031..033** signal bundle for release-time visibility — strictly stronger than **`azure-release-hardening-2`** (which lacks freshness, service-connection decomposition, and artifact SBOM/provenance gates).

**Manual vs API-backed Azure evidence**: **`collect-evidence --platform azure`** stamps **`attested_by: azure-devops-api-collection`**, **`collection`**, and **`posture_support`** on branch-policy and pipeline-governance JSON. Evaluators use that to distinguish **LIVE** (`pass` + higher confidence) from **manual** templates (**`self-attested`** / **`manual-review-required`** when APIs were partial). Controls **AZ-SEC-031**, **AZ-SCA-032**, and **AZ-SBOM-033** remain **`assurance: signal`** regardless of profile.

Bundled policy data lives in:

- `src/oss_policy_kit/data/controls/catalog.yaml`
- `src/oss_policy_kit/data/profiles/*/profile.yaml`

## How To Interpret Results

Each control resolves to one of these states:

| Status | Meaning |
| --- | --- |
| `pass` | A positive local signal was observed |
| `fail` | A required signal was missing or a high-signal problem was detected |
| `manual-review-required` | The control cannot be safely confirmed from a clone alone; review manually |
| `self-attested` | Local evidence exists, but trust still depends on maintainer honesty or platform confirmation |
| `not-observable` | The control exists conceptually but is not locally observable |
| `not-applicable` | The control does not apply to the evaluated repository shape |
| `waived` | A documented exception overrode a non-pass outcome |

Reports include:

- evidence sources
- confidence
- reason
- remediation text
- waiver metadata when applicable

### What The Kit Can Observe Locally

- tracked governance files
- workflow YAML structure and static content
- optional local evidence files
- optional waiver registry
- optional Scorecard JSON used as supplemental evidence

### What The Kit Cannot Prove From A Clone Alone

- live GitHub branch protection or rulesets
- organization-level policies outside the clone
- runtime behavior of reusable workflows or complex expressions
- compliance or certification against a formal framework

### `all-pass` On `github-level-1` vs `github-release-hardening-1`

- `github-level-1` currently evaluates 14 active controls. `all-pass` means fourteen `pass` outcomes for that profile on the current revision.
- `github-release-hardening-1` adds `PLAT-BRPROT-015`. Branch protection is enforced on GitHub, not in the clone, so a strong local repository can still end with `pass` plus `manual-review-required` or `self-attested` for that control.

That behavior is intentional. It is the tool being honest, not a defect.

### GitHub Profile Ladder

- `github-level-1`: pragmatic baseline with clone-visible governance and CI hygiene.
- `github-level-2`: adds stricter workflow hardening (`GH-WF-018` to `GH-REL-021`).
- `github-level-3`: adds strict deployment identity and provenance expectations (`GH-DEPLOY-022`, `GH-PROV-023`).
- `github-release-hardening-1`: level-1 + branch-protection evidence/manual-review.
- `github-release-hardening-2`: level-2 + platform evidence controls (`GH-PLAT-024..026`).
- `github-release-hardening-3`: level-3 + platform evidence controls (`PLAT-BRPROT-015`, `GH-PLAT-024..026`).

### When `self-attested` Is Normal

Examples:

- `GOV-WAIV-014` as **`manual-review-required`** when no versioned in-repo waiver policy file is present (optional governance, but explicitly surfaced)
- `PLAT-BRPROT-015` when local evidence JSON exists but platform truth still needs confirmation in GitHub

## Adoption Paths

| Path | What to copy | Expected `github-level-1` outcome |
| --- | --- | --- |
| Minimal | Governance docs only, or CI without SBOM/security coverage | Useful gap analysis, but often fewer than 14 `pass` |
| Recommended | `templates/workflows/ci.yml`, `templates/workflows/security.yml`, `templates/waivers/waivers.yaml`, plus docs/templates as needed | Target `pass: 14` for a standard Python `src/` layout on `github-level-1` |
| Hardening | Recommended path plus optional `.oss-policy-kit/evidence/branch-protection.json` and the `github-release-hardening-1` profile | Expect strong results plus a platform-related non-pass state when proof remains local-only |

Recommended entry points:

- [docs/adoption-guide.md](docs/adoption-guide.md)
- [docs/recommended-adoption-playbook.md](docs/recommended-adoption-playbook.md)

## Applicability

This kit evaluates OSS repository posture and clone-visible CI/CD hygiene from a local clone.

It is a good fit for repositories that want:

- explicit governance
- review ownership
- CI hygiene
- release evidence

It is not a full application security assessment.

A generic internal app, lab, or service without `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, GitHub workflows, or changelog artifacts will often show many failures by design. That means OSS-style repository evidence is missing. It does not mean the runtime system is comprehensively insecure.

Use the results to improve:

- repository hygiene
- PR and CI posture
- evidence collection
- release preparation

Do not use the results as a substitute for:

- threat modeling
- secure code review
- platform configuration review
- cloud or infrastructure assessment
- penetration testing

## Automation Limits

Local evaluation can inspect only what exists in the working tree. It cannot reliably prove:

- GitHub branch protection or rulesets
- GitHub Advanced Security feature enablement
- organization-level policies outside the clone
- runtime behavior of reusable workflows, composite actions, or expression-heavy logic

For those areas, the kit intentionally uses:

- `manual-review-required`
- optional `self-attested` evidence
- optional supplemental context such as Scorecard JSON

## Examples And Fixtures

- `examples/hardened-repo` demonstrates a strong baseline and should pass `github-level-1`
- `examples/vulnerable-repo` demonstrates obvious gaps and is useful for testing CI gates
- `tests/fixtures/repositories/` contains edge-case repository shapes used by the test suite

## Repository Layout

```text
src/oss_policy_kit/        Python package (domain, application, adapters, infrastructure, CLI)
src/oss_policy_kit/data/   Bundled policy data (catalog and profiles)
templates/                 Governance docs, workflow examples, waiver template, ruleset examples
examples/                  Vulnerable and hardened sample repositories
tests/fixtures/            Static fixtures, including repository-shaped test inputs
waivers/                   Example and active waiver registries
reports/schema/            Public JSON Schema for evaluation output
docs/                      Supporting technical documentation
gitpage/                   Optional Vite/React site for GitHub Pages (not part of the Python package)
```

### Working tree layout

Keep generated artifacts (`out/`, `artifacts/`, `dist/`, caches, and `*.egg-info/`) untracked during local work.  
The `screenshots/` directory is intentionally versioned because it is part of the public README walkthrough.

### Public repository hygiene

Only product source, packaged policy data, public documentation, examples, templates, tests, screenshots, workflow definitions, and the optional `gitpage/` site should be versioned. Local assistant state, private planning notes, generated validation reports, build outputs, dependency folders, caches, local secrets, and maintainer-only scratch directories must stay ignored and must not be recovered into the public mirror.

## Documentation

- [docs/README.md](docs/README.md) - documentation hub
- [Project site](https://lucashgrifoni.github.io/OSS-Security-Policy-as-Code-Starter-Kit/) - public product site
- [docs/profiles/overview.md](docs/profiles/overview.md) - bundled profiles matrix, assurance vocabulary, decision tree
- [docs/profiles/github.md](docs/profiles/github.md) / [docs/profiles/aws.md](docs/profiles/aws.md) / [docs/profiles/azure.md](docs/profiles/azure.md) - operator guides by platform family
- [docs/release-playbook-hardgate.md](docs/release-playbook-hardgate.md) - release gate with real CLI commands
- [docs/release-hardening-workflow.md](docs/release-hardening-workflow.md) - end-to-end L3 and release-hardening workflow with evidence paths
- [docs/adoption-guide.md](docs/adoption-guide.md) - baseline selection and expected outcomes
- [docs/recommended-adoption-playbook.md](docs/recommended-adoption-playbook.md) - copy/paste adoption path
- [docs/architecture.md](docs/architecture.md) - package boundaries, trust model, and evidence semantics
- [docs/packaging-and-release.md](docs/packaging-and-release.md) - install, build, and distribution guidance
- [docs/release-readiness.md](docs/release-readiness.md) - release gate and public launch checks
- [docs/public-release-readiness.md](docs/public-release-readiness.md) - mandatory hard gate for the first public repository launch
- [docs/publication-traceability-matrix.md](docs/publication-traceability-matrix.md) - promise-to-evidence mapping for the release candidate
- [ROADMAP.md](ROADMAP.md) - public roadmap and post-publication maintenance governance

## Maintainer Self-Check

Run the kit against this repository:

```bash
python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck
```

Treat the generated self-check report as authoritative for the current revision. This repository aims to stay close to `github-level-1`, but workflow drift and evidence choices can change the exact summary.

### Evaluation Report `schema_version`

JSON reports default to `schema_version` with the suffix **`reports/0.3`** ( **`live_collection`**, per-control **`evidence_collection_method`**, **`summary_by_gate_role`**, **`gate_execution_model`** ). Use **`evaluate --report-json-contract 0.2`** or **`0.1`** when you need an older wire shape. The suffix identifies the report contract under `docs/reports-contract-v0.3.md` / `reports/schema/`; it is not the Python package version.

### Report JSON schema

Top-level keys in the current report contract:

- `schema_version`: identifies the report wire contract URL (`reports/0.1`, `0.2`, or `0.3`).
- `generated_at`: UTC timestamp for report generation.
- `kit_version`: OSS Policy Kit version used in evaluation.
- `target_path`: absolute evaluated repository path.
- `profile_id`: bundled or custom profile id used in the run.
- `profile_title`: human title of the selected profile.
- `summary_by_status`: aggregate counts by status value (`pass`, `fail`, etc.).
- `results`: per-control result array (**controls live under `results`, not under `controls`**).
- `operational_warnings`: non-blocking warnings surfaced during evaluation.
- `scorecard_path`: resolved path to Scorecard JSON when provided (else null).
- `scorecard_supplemental`: summary of scorecard influence on outcomes (else null).
- `external_waiver_path`: path to externally supplied `--waivers` file (else null).
- `action_insights`: suggested next actions derived from result patterns.
- `live_collection`: metadata about API-backed evidence collection when available (else null).
- `weighted_score`: risk-adjusted scoring block (`earned`, `possible`, `percent`).
- `summary_by_gate_role`: `reports/0.3` gate-role aggregation for CI semantics.
- `gate_execution_model`: `reports/0.3` documentation object for `--fail-on` mapping.

## Release Line And Semver

The `4.x` line is the current stable major line of the project.

Semver intent:

- MAJOR for incompatible public changes
- MINOR for backward-compatible additions
- PATCH for fixes, hardening, documentation, templates, and operational improvements

For the exact released version, see:

- [CHANGELOG.md](CHANGELOG.md)
- GitHub Releases

## Project Status

This project is published, maintained, and intentionally scoped.

It prioritizes:

- clarity over hype
- evidence over vague scoring
- explicit limits over fake assurance

Planned evolution stays conservative and is tracked through released changes, public documentation, and [ROADMAP.md](ROADMAP.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
