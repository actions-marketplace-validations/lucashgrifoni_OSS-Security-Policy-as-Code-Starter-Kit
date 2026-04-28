# OSPS mapping notes (honest scope)

The [OpenSSF OSPS Baseline](https://baseline.openssf.org/) is a useful reference framework. This project **does not** claim to implement OSPS end-to-end, and it **does not** certify OSPS conformance.

## What `v0.1.0` provides

A **starter mapping posture**:

- Controls are labeled in `src/oss_policy_kit/data/controls/catalog.yaml` with an `automation` hint:
  - `automated` (local signals are strong)
  - `partially_observable` (heuristics or supplemental evidence)
  - `human_or_policy` (process-dependent)
  - `not_observable_locally` (platform settings)

## Example intent (not exhaustive)

| This kit control | OSPS theme (high level) | Automation posture |
| --- | --- | --- |
| `GOV-SEC-001` | Governance / disclosure | Automated (file presence) |
| `GOV-DISC-013` | Vulnerability reporting | Partially observable (heuristic) |
| `CI-*` | Build & release / SCM hardening | Automated (static workflow scan) |
| `SEC-CODEQL-010` | Vulnerability management | Partially observable |
| `PLAT-BRPROT-015` | Access control / SCM policy | Manual review (local clone insufficient) |

## How to use this document

Use it to explain **alignment** and **coverage gaps** to stakeholders, especially the difference between:

- controls that can be **machine-checked** in a clone
- controls that require **platform configuration**
- controls that require **human process** evidence
