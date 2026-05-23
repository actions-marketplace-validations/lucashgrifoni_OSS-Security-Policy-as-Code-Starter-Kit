# Profile maturity - deferred follow-ups

Items intentionally deferred in earlier documentation rounds. Several items below are **targeted for the v4.0.0 major** on this branch; treat user-facing guarantees as tied to **`CHANGELOG.md`** and the eventual **`v4.0.0` tag**, not an implied PyPI publication date.

## CLI and listing

- *(Shipped)* `profiles` flags `--only-extreme`, `--advisory-only`, `--family`, plus `--format json` posture metadata.
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

## Future considerations (post-v5.0.0, not in current scope)

These are conceptual follow-ups identified during the 2026-05-06 raio-x. They are **not** scheduled and **not** part of v5.0.0. They are listed here to make the boundary between current behavior and possible future work explicit.

- Renaming hybrid profiles (`github-aws-level-2`, `github-azure-level-2`) to make their advisory-only intent unambiguous in the name. This would be a breaking change requiring a deprecation window.
- Automatic verification that evidence JSON files have been filled (vs. still containing template placeholders). Today this is surfaced by `evaluate` as `manual-review-required`; making it a precondition would require either a new control or a new flag.
- A `--strict` or `--require-filled-evidence` flag for `recommend-profile` so it suppresses `release-hardening-*` suggestions when evidence files appear unfilled. The current rationale text now warns about this, but does not enforce it.
- Closing the AWS / Azure collector parity gap with the GitHub collector (additional `collect-evidence` endpoints for richer attestations).
- Runtime enforcement of `posture: advisory` so `--fail-on fail` paired with an advisory profile emits an explicit warning instead of silently honoring the threshold.
- *(Shipped)* A regenerable `docs/controls-catalog.md` script — `scripts/generate-controls-catalog.py`.

## `emit-vex` subcommand — v0.1 shipped v5.9.0; the planned extensions shipped too

`emit-vex` shipped in v5.9.0; see [`../vex-emission.md`](../vex-emission.md). Findings without a matching waiver are emitted as `analysis.state: in_triage` — the manufacturer fills the analysis post-hoc.

The three additive extensions originally tracked here have all shipped (non-breaking):

1. **Per-CVE waivers** — the `waivers/waivers.yaml` schema accepts `vulnerability_ids: [...]`; `emit-vex --waivers` then sets `analysis.state: not_affected` plus a CycloneDX `analysis.justification` enum value derived from the waiver text.
2. **`--validate`** — round-trips output through the CycloneDX 1.6 JSON Schema before exit.
3. **`--include-references`** — embeds advisory URLs (`osv.dev`, `github.com/advisories/...`) where OSV-Scanner provides them in SARIF `helpUri` / `properties`.

Tracked in [`../decisions/adr-002-emit-vex-scope.md`](../decisions/adr-002-emit-vex-scope.md).

## GitLab CI support (full first-class family — shipped)

GitLab CI support shipped and reached **full parity** with the GitHub / Azure / AWS families: the `gitlab-level-1` profile landed in v5.9.0, `gitlab-level-2` in v6.0.0, `gitlab-level-3` in v6.3.0, and the parallel **`gitlab-release-hardening-1/2/3`** track plus a dedicated **evidence collector** (`collect-evidence --platform gitlab`) and scaffold templates (`scaffold-evidence --platform gitlab`) landed afterwards. A dedicated `.gitlab-ci.yml` parser and the `GL-PIPE-*` control family back these profiles — they were **not** composed from GitHub-only controls, preserving the assurance-grade promise. The work split that landed this:

1. A `.gitlab-ci.yml` parser in `oss_policy_kit/infrastructure/` (mirrors `workflow_parser.py` / `azure_pipeline_parser.py`).
2. GitLab-prefixed controls (`GL-PIPE-*` family) for permissions, includes, image pinning, secret handling, runner tags, and merge-request rules.
3. The parser plus the controls populate the bundled `gitlab-level-*` and `gitlab-release-hardening-*` profiles.
4. A `GitLabEvidenceCollector` that retrieves `branch-protection`, `gitlab-mr-rules`, and `org-mfa-posture` evidence from the GitLab REST API (`read_api` + group read). See [collector-parity.md](../collector-parity.md).
5. `recommend-profile`, `init --platform gitlab`, `scaffold-evidence`, and `collect-evidence` all treat GitLab as a first-class platform.
6. Tests parallel to the other platform families for the GitLab parser, profiles, and collector.

## GitHub native security platform features (GA-dependent, planned)

The GitHub 2026 Security Roadmap announced four native platform features that overlap with controls this kit currently expresses indirectly. Implementation is **deferred until GitHub ships GA** of each feature — building against preview/beta APIs would force rewrites once the final surface lands.

- **`GH-EGRESS-001`** — Native Layer-7 egress firewall (operates outside the runner VM). The kit currently has no direct control for this; `signal`-grade detection of [Harden-Runner](https://github.com/step-security/harden-runner) usage is the interim recommendation expressed via documentation, not a control. When the native feature reaches GA, this control will read the workflow-level egress allowlist and surface it as `evidence-backed` for hosted runners.
- **`GH-SECRETS-SCOPED-001`** — Scoped secrets. Today the kit covers token-permissions breadth via `CI-PERM-006`, `CI-LEAST-009`, and `GH-WF-020`; scoped secrets is a separate concept (which secrets are reachable from a job) that requires the native scoping feature to be observable from the workflow YAML.
- **`GH-WF-LOCKED-001`** — Workflow dependency locking. Complements `CI-PIN-008` and `CI-WFCALLSHA-055` by adding lockfile-style guarantees beyond SHA pinning. Will be introduced once the lockfile format is published.

The kit will register these as `deterministic` or `evidence-backed` (not `signal`) once the underlying GitHub features are GA, to preserve the project's stance that new controls should not inflate maturity with directional-only signals.
