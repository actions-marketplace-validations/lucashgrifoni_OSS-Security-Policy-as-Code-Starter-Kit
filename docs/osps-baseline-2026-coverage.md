# OSPS Baseline v2026.02.19 coverage (advisory)

> **Advisory mapping only. Each entry records that a bundled kit control provides a clone-visible signal toward an OSPS Baseline criterion; it is not a certification of OSPS conformance and does not guarantee any OSPS maturity level. Coverage maps the criteria that are expressible from a clone, never the whole baseline. Gaps are real and intentional.**

Generated from [`src/oss_policy_kit/data/frameworks/osps-baseline-2026.yaml`](../src/oss_policy_kit/data/frameworks/osps-baseline-2026.yaml) and the bundled control catalog. Per-control assurance is read live from the catalog. Regenerate with `python scripts/generate-osps-coverage.py` whenever the map, catalog, or profile changes.

> For a quick terminal view of the same data, run `oss-policy-kit osps-coverage` (`--format json` for the full machine-readable map).

- **OSPS Baseline snapshot:** `v2026.02.19` ([v2026.02.19](https://github.com/ossf/security-baseline/releases/tag/v2026.02.19))
- **Aligned kit profile:** `osps-baseline-2026-1`
- **Criteria in snapshot:** 41 across 8 families (AC, BR, DO, GV, LE, QA, SA, VM)

## Coverage by maturity level

"With kit signal" counts OSPS criteria for which at least one bundled control provides a clone-visible signal. It is **not** a count of satisfied criteria and **not** a conformance level — a signal is necessary context, not proof.

| OSPS level | Criteria in level | With kit signal | Not yet expressed |
|---|---:|---:|---:|
| L1 | 17 | 11 | 6 |
| L2 | 32 | 18 | 14 |
| L3 | 40 | 22 | 18 |

## Per-criterion map

Every OSPS Baseline v2026.02.19 criterion, in upstream order. The **Kit signal** column lists the bundled control(s) that provide a clone-visible signal toward the criterion, with each control's catalog assurance class in parentheses; `-- not expressed` marks an honest gap.

| Criterion | Levels | Objective | Kit signal (assurance) |
|---|---|---|---|
| `OSPS-AC-01` | 1, 2, 3 | Reduce account compromise risk via multi-factor authentication | `ORG-MFA-001` (evidence-backed) |
| `OSPS-AC-02` | 1, 2, 3 | Minimize unauthorized access through restricted repository permissions | `GH-PLAT-024` (evidence-backed), `GOV-COWN-003` (deterministic) |
| `OSPS-AC-03` | 1, 2, 3 | Prevent accidental primary-branch modification or deletion | `GH-PLAT-024` (evidence-backed), `PLAT-BRPROT-015` (evidence-backed) |
| `OSPS-AC-04` | 2, 3 | Limit CI/CD pipeline permissions to the minimum needed | `CI-PERM-006` (deterministic) |
| `OSPS-BR-01` | 1, 2, 3 | Prevent untrusted input in build and release pipelines | `CI-PIN-008` (deterministic) |
| `OSPS-BR-02` | 2, 3 | Assign unique version identifiers to releases | _-- not expressed_ |
| `OSPS-BR-03` | 1, 2, 3 | Use encrypted channels for development activity | _-- not expressed_ |
| `OSPS-BR-04` | 2, 3 | Publish a changelog with software releases | `REL-CHANGE-012` (deterministic) |
| `OSPS-BR-05` | 2, 3 | Use standardized dependency management tooling | `DEP-UPDATE-001` (deterministic), `SEC-DEPREV-011` (deterministic) |
| `OSPS-BR-06` | 2, 3 | Include signatures and hashes with releases | `GH-PROV-023` (evidence-backed) |
| `OSPS-BR-07` | 1, 3 | Secure secrets and credentials in the project | `SEC-SECRETS-050` (signal) |
| `OSPS-DO-01` | 1, 2, 3 | Comprehensive user guides for basic functionality | _-- not expressed_ |
| `OSPS-DO-02` | 1, 2, 3 | Enable defect-reporting mechanisms for users | _-- not expressed_ |
| `OSPS-DO-03` | 3 | Enable verification of software authenticity and integrity | _-- not expressed_ |
| `OSPS-DO-04` | 3 | Communicate support lifecycle expectations clearly | _-- not expressed_ |
| `OSPS-DO-05` | 3 | Document security update scope and duration | _-- not expressed_ |
| `OSPS-DO-06` | 2, 3 | Describe dependency selection and tracking methods | _-- not expressed_ |
| `OSPS-DO-07` | 2, 3 | Provide source-code build instructions | `GOV-BUILD-072` (signal) |
| `OSPS-GV-01` | 2, 3 | Publish project roles and responsibilities | _-- not expressed_ |
| `OSPS-GV-02` | 1, 2, 3 | Enable public discussion mechanisms for feedback | _-- not expressed_ |
| `OSPS-GV-03` | 1, 2, 3 | Publish a contribution guide | `GOV-CON-002` (deterministic) |
| `OSPS-GV-04` | 3 | Vet contributors before granting elevated access | _-- not expressed_ |
| `OSPS-LE-01` | 2, 3 | Require contributors to assert legal right to commit | _-- not expressed_ |
| `OSPS-LE-02` | 1, 2, 3 | Ensure project licenses meet OSI or FSF definitions | `GOV-LIC-004` (deterministic) |
| `OSPS-LE-03` | 1, 2, 3 | Maintain licenses in well-known locations | `GOV-LIC-004` (deterministic) |
| `OSPS-QA-01` | 1, 2, 3 | Enable source-code access and review for transparency | _-- not expressed_ |
| `OSPS-QA-02` | 1, 2, 3 | Provide transparency on project dependencies | `BUILD-SBOM-QUAL-003` (signal) |
| `OSPS-QA-03` | 2, 3 | Ensure automated checks pass before accepting changes | `SEC-DEPREV-011` (deterministic) |
| `OSPS-QA-04` | 1, 2, 3 | Hold all codebases to consistent security standards | `SEC-CODEQL-010` (signal) |
| `OSPS-QA-05` | 1, 2, 3 | Remove generated executables and unreviewable binaries | _-- not expressed_ |
| `OSPS-QA-06` | 2, 3 | Run automated testing in CI/CD before merges | `CI-WF-005` (deterministic) |
| `OSPS-QA-07` | 3 | Require non-author human approval before merging | `GOV-COWN-003` (deterministic) |
| `OSPS-SA-01` | 2, 3 | Document system actors and actions (design) | _-- not expressed_ |
| `OSPS-SA-02` | 2, 3 | Describe external interfaces for integration | _-- not expressed_ |
| `OSPS-SA-03` | 2, 3 | Perform security assessment and threat modeling | _-- not expressed_ |
| `OSPS-VM-01` | 2, 3 | Establish a coordinated vulnerability disclosure policy | `GOV-DISC-013` (signal) |
| `OSPS-VM-02` | 1 | Publish security contacts and reporting process | `GOV-SEC-001` (deterministic) |
| `OSPS-VM-03` | 2, 3 | Provide a private vulnerability reporting mechanism | `GOV-DISC-013` (signal) |
| `OSPS-VM-04` | 2, 3 | Ensure public visibility of discovered vulnerabilities | _-- not expressed_ |
| `OSPS-VM-05` | 3 | Define and enforce dependency remediation thresholds | `DEP-UPDATE-001` (deterministic) |
| `OSPS-VM-06` | 3 | Define and enforce application security testing policy | `SEC-CODEQL-010` (signal) |

## Honest gaps

18 of 41 criteria have no clone-visible kit signal. These are real and intentional: the kit does not assess them from a clone (e.g. user-documentation quality, threat modeling, encrypted dev channels, contributor vetting). They are listed so adopters know what the kit does **not** cover.

| Family | Uncovered criteria |
|---|---|
| BR | `OSPS-BR-02`, `OSPS-BR-03` |
| DO | `OSPS-DO-01`, `OSPS-DO-02`, `OSPS-DO-03`, `OSPS-DO-04`, `OSPS-DO-05`, `OSPS-DO-06` |
| GV | `OSPS-GV-01`, `OSPS-GV-02`, `OSPS-GV-04` |
| LE | `OSPS-LE-01` |
| QA | `OSPS-QA-01`, `OSPS-QA-05` |
| SA | `OSPS-SA-01`, `OSPS-SA-02`, `OSPS-SA-03` |
| VM | `OSPS-VM-04` |

## Aggregate conformance signal

- `OSPS-SCORECARD-V6-001` — Consumes scorecard --format=osps conformance verdict (all families) when evidence present; manual review otherwise.

The aggregate control consumes an external OpenSSF Scorecard v6 OSPS conformance verdict when present; it is **not** counted toward per-criterion coverage above because it asserts the upstream verdict, not a specific clone-visible criterion. A machine-readable conformance renderer matching the Scorecard v6 `--format=osps` wire shape is intentionally deferred until that format reaches GA (see ADR-018).

