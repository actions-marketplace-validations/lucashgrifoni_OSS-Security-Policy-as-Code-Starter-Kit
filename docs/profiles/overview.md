# Profiles overview

This page summarizes the **21 bundled profiles** in this kit build: deterministic ladder profiles per platform (`github-*`, `azure-*`, `aws-*`), two **advisory-only hybrid** profiles, and one **legacy bundled id** that remains for compatibility.

## Assurance vocabulary

- **deterministic**: evaluated from files in the clone (YAML, manifests, paths) with structured parsing where possible.
- **signal**: keyword or heuristic posture in CI files; PASS is directional, not proof of execution.
- **evidence-backed**: requires `.oss-policy-kit/evidence/*.json` (manual attestation or `collect-evidence` API exports) for a credible PASS.

## Profile ladder vocabulary

- **starter** (`level-1`, `release-hardening-1`): smallest honest gate focused on clone-visible governance plus baseline CI signals.
- **advisory** (`level-2`, `release-hardening-2`): adds stricter workflow posture; still contains signal-heavy controls.
- **hard-gate** (`level-3`): evidence-first core; treat failures as merge/release blockers when your team accepts residual signal risk.
- **release-hardening**: parallel track that layers release discipline (freshness, branch protection evidence, merge queue, artifact-bound SBOM/provenance on AWS/Azure) on top of the same ladder.

Hybrid profiles **github-aws-level-2** and **github-azure-level-2** are **advisory-only by design** (they combine GitHub workflows with AWS/Azure clone signals and never replace the pure level-3 gates).

## Operational usage matrix

Use this matrix as an operator shortcut (derived from current bundled profile intent and fixture behavior):

| Usage class | Profiles | Notes |
| --- | --- | --- |
| Daily baseline | `*-level-1`, `*-level-2`, `*-release-hardening-1`, `*-release-hardening-2` | Best for routine triage and incremental hardening. |
| Extreme hard-gate | `*-level-3`, `*-release-hardening-3` (single-platform) | Evidence-first posture; treat non-pass rows and warnings as real work. |
| Advisory-only | `github-aws-level-2`, `github-azure-level-2` | Multi-platform guidance; **not** a hard-gate replacement. |
| Legacy compatibility id | `github-release-hardening` | Supported alias of `github-release-hardening-1`; prefer canonical id for new automation/docs. |

## `maturity_label` glossary and recommended `--fail-on`

`python -m oss_policy_kit profiles --format json` exposes a `maturity_label` field per profile. The label is a stable operator-facing string; the table below maps each label to the gate we recommend you actually wire in CI.

| `maturity_label` | Example profiles | Recommended `--fail-on` | Evidence expectation |
| --- | --- | --- | --- |
| `starter ladder` | `github-level-1`, `azure-level-1`, `aws-level-1` | `fail` | Clone-visible signals only. |
| `advisory ladder` | `github-level-2`, `azure-level-2`, `aws-level-2` | `degraded` (treat `manual-review-required` as a gate too) | Signal-heavy; live evidence is optional. |
| `hard-gate ladder (extreme)` | `github-level-3`, `azure-level-3`, `aws-level-3` | `fail` paired with `collect-evidence` live for that family | Evidence-first; `self-attested` is not `pass` at this tier. |
| `release ladder` | `*-release-hardening-1`, `*-release-hardening-2` | `fail` (release-hardening-1) or `degraded` (release-hardening-2) | Clone signals plus minimal release evidence; freshness matters. |
| `release hard-gate (extreme)` | `*-release-hardening-3` | `fail` paired with `collect-evidence` live + artifact-bound SBOM/provenance | Strictest bundled release gate per platform. |
| `advisory hybrid (multi-platform)` | `github-aws-level-2`, `github-azure-level-2` | `degraded` only — **never** use as the hard-gate for a release | GitHub + AWS/Azure signals combined; advisory by design. |
| `legacy bundled id (non-canonical)` | `github-release-hardening` | Same as the canonical profile it aliases (`github-release-hardening-1`) | Same as canonical. Prefer the canonical id in new automation. |

Multi-platform hybrids deserve a short note of their own: **`github-aws-level-2`** and **`github-azure-level-2`** exist for teams whose source of truth is GitHub (repo lives on github.com) but whose CI/CD terminates on AWS CodePipeline or Azure Pipelines. They stack GitHub workflow signals on top of the platform family's clone-visible controls and are **advisory by design**. Use them as a PR-level gate with `--fail-on degraded`; when it is time to cut a release, pick the pure single-platform hard-gate (`aws-release-hardening-3` or `azure-release-hardening-3`) for the environment that actually ships the artifact.

## Hybrid (PR-time) vs single-platform extreme (release-time)

The hybrid profiles `github-aws-level-2` and `github-azure-level-2` are advisory by design. Use them as a PR-time gate when source lives on GitHub but CI/CD runs on AWS or Azure. They do not replace the single-platform extreme profile of the platform that actually ships the release artifact.

Operational rule of thumb:

- PR-time, multi-platform team: `github-aws-level-2` (or `github-azure-level-2`) with `--fail-on degraded`.
- Release-time, deterministic gate: `aws-release-hardening-3` (or `azure-release-hardening-3`) with `--fail-on fail` and a real `collect-evidence` run for that platform.

The hybrid is a triage profile; the single-platform extreme is the gate.

When you choose to wire a hybrid profile in CI, prefer `--fail-on degraded` over `--fail-on fail`. The advisory tier is signal-heavy: `manual-review-required` is the dominant useful state, and `--fail-on degraded` gates it without forcing the team to handle every signal as a blocker.

## Uniform output in `*-level-1` on bare application repos

`*-level-1` is optimized for repositories that carry their **own** governance (SECURITY.md, CONTRIBUTING, CODEOWNERS, LICENSE, CHANGELOG) and, for `github-level-1`, their own `.github/workflows/`. In a monorepo where individual sub-apps are pure code trees (no governance, no CI at the sub-app level, no `.git`), every sub-app tends to produce the **same** `*-level-1` report — most rows `fail` because the clone-visible signals simply are not there. That is **not** a bug and **not** a regression: it reflects that `*-level-1` was never designed to grade bare application code by itself.

If you hit this pattern, the honest moves are:

- keep governance in an **umbrella** repository and only run `*-level-1` against that umbrella,
- escalate bare application sub-trees to `*-level-2` with `--fail-on degraded` (advisory) so the uniform-fail tail is read as signal rather than a hard fail, or
- treat each sub-app independently with a profile that matches its real CI platform and run `evaluate` per sub-tree instead of `evaluate-many` at the parent.

### How to recognize it in a batch

If `evaluation-batch.md` shows several targets failing the same set — typically `GOV-COWN-003`, `GOV-WAIV-014`, `GOV-CON-002`, `GOV-DISC-013`, `GOV-LIC-004`, `GOV-SEC-001`, `REL-CHANGE-012` — that is the expected `*-level-1` shape on bare application code, **not** a kit defect or regression. Apply one of the moves above instead of treating it as noise.

## Matrix (derived from bundled YAML + catalog assurance mix)

| Profile | Controls | Status (CLI `maturity_label`) | Extreme gate profile? | det / sig / evi |
| --- | ---: | --- | --- | --- |
| github-level-1 | 14 | starter ladder | no | 11 / 3 / 0 |
| github-level-2 | 29 | advisory ladder | no | 19 / 10 / 0 |
| github-level-3 | 33 | hard-gate ladder (extreme) | **yes** | 21 / 8 / 4 |
| github-release-hardening-1 | 16 | release ladder | no | 12 / 3 / 1 |
| github-release-hardening-2 | 30 | release ladder | no | 18 / 8 / 4 |
| github-release-hardening-3 | 32 | release hard-gate (extreme) | **yes** | 19 / 8 / 5 |
| github-release-hardening | 16 | legacy bundled id (non-canonical) | no | 12 / 3 / 1 |
| github-aws-level-2 | 35 | advisory hybrid (multi-platform) | no | 22 / 13 / 0 |
| github-azure-level-2 | 36 | advisory hybrid (multi-platform) | no | 23 / 12 / 1 |
| azure-level-1 | 13 | starter ladder | no | 9 / 4 / 0 |
| azure-level-2 | 21 | advisory ladder | no | 15 / 5 / 1 |
| azure-level-3 | 27 | hard-gate ladder (extreme) | **yes** | 16 / 3 / 8 |
| azure-release-hardening-1 | 17 | release ladder | no | 11 / 4 / 2 |
| azure-release-hardening-2 | 24 | release ladder | no | 16 / 5 / 3 |
| azure-release-hardening-3 | 30 | release hard-gate (extreme) | **yes** | 16 / 6 / 8 |
| aws-level-1 | 12 | starter ladder | no | 8 / 4 / 0 |
| aws-level-2 | 20 | advisory ladder | no | 14 / 6 / 0 |
| aws-level-3 | 25 | hard-gate ladder (extreme) | **yes** | 15 / 3 / 7 |
| aws-release-hardening-1 | 16 | release ladder | no | 10 / 4 / 2 |
| aws-release-hardening-2 | 22 | release ladder | no | 14 / 6 / 2 |
| aws-release-hardening-3 | 29 | release hard-gate (extreme) | **yes** | 15 / 7 / 7 |

> **Source for counts**: `python -m oss_policy_kit profiles --format json` (`controls` and `assurance_mix`) against the bundled catalog in this revision.

## ASCII decision tree (choose a profile)

```
Do you have GitHub Actions workflows in the clone?
├─ No -> you are probably not a github-* candidate; look at Azure/AWS signals.
└─ Yes
   ├─ Baseline OSS clone + CI only? -> github-level-1
   ├─ Stronger signals (merge queue, secrets hygiene) without platform evidence? -> github-level-2
   └─ Want GitHub evidence (.oss-policy-kit/evidence) + org MFA + SBOM on disk?
      ├─ Release pipeline focus -> github-release-hardening-3 (densest reference)
      └─ Repo service focus -> github-level-3

Need AWS or Azure evidence-backed gates?
└─ Use matching aws-* / azure-*; GitHub remains the most mature path *inside this kit*.
```

## Zero `fail` is not the same as all-pass

In reports, **`summary_by_status.fail == 0`** only means no control ended in **`fail`**. The same run can still contain **`self-attested`**, **`manual-review-required`**, **`not-evaluated`**, **`not-applicable`**, and operational warnings. The bundled `examples/hardened-repo` fixture is intentionally tuned so the **six extreme profiles** reach **zero `fail`** while remaining honest about non-pass rows (especially **AWS/Azure**, which lean more on self-attested evidence than **GitHub** in synthetic setups).

## Fixture representativity (important)

The hardened fixture is strong for the single-platform extreme tracks, but it is **not** a universal “green for every profile” fixture.

- Confirmed in the 2026-04-22 validation: `github-level-2`, `github-release-hardening-2`, `github-aws-level-2`, and `github-azure-level-2` can still fail in `examples/hardened-repo` (notably on `GH-PROV-023` and/or `SEC-SECRETS-050`).
- Re-confirmed on 2026-04-24: `github-aws-level-2` keeps two fixture-only fails (`provenance/attestation` and `secret scanning keyword`); the same pattern holds for `github-azure-level-2`. The fixture remains intentional and is not a profile defect.
- That does **not** mean those profiles are broken; it means this fixture does not fully represent every L2/hybrid expectation.
- Treat fixture gaps and profile quality separately. When a profile is advisory-only by design, a non-green fixture run may still be useful for prioritization.

## Honest limits for this kit

- Evidence under `examples/hardened-repo` is **synthetic** (it does not replace `collect-evidence` with real credentials).
- **OSS-SCORECARD-001** stays **not-evaluated** until you pass `--scorecard-json`.
- Extreme AWS/Azure profiles need more **evidence discipline** than GitHub to reach the same operational confidence. See [docs/profiles/aws.md](aws.md) and [docs/profiles/azure.md](azure.md) for the explicit `collect-evidence` expectation at L3 / release-hardening-3.

## How `recommend-profile` reads `.oss-policy-kit/evidence/`

`recommend-profile` treats JSON files under `.oss-policy-kit/evidence/` as platform signals (github-shaped JSON -> github family, azure-shaped -> azure, aws-shaped -> aws). Because of that, a repository with only a synthetic evidence pack (and no real workflow, pipeline or buildspec) can still receive a `*-release-hardening-2` suggestion. The suggestion text uses "and/or" to reflect this; the heuristic does not know whether the JSON came from a template or from `collect-evidence`.

Operational rule: treat any `*-release-hardening-*` suggestion as a hypothesis. Confirm there is a real CI workflow / pipeline / buildspec in the repository before promoting that profile to a hard gate. If you only have synthetic evidence, start at the matching `*-level-1` and let the team produce real CI signals before climbing the ladder.

## Further reading

- [GitHub profiles](github.md)
- [AWS profiles](aws.md)
- [Azure profiles](azure.md)
- [Release hard-gate playbook](../release-playbook-hardgate.md)
- [Deferred follow-ups (out of scope)](deferred-followups.md)
