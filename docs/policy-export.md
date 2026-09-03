# Policy export (`export-policy`)

> **Available since v7.0.0.** `export-policy` renders a **profile** into a
> best-effort policy **skeleton** for an external engine (OPA/Conftest via Rego,
> or Kyverno/cel-go via CEL). See ADR-035 for the design rationale.

Unlike [`export-evidence`](evidence-export.md), which consumes an evaluation
*report*, `export-policy` consumes a *profile + catalog* — the policy
*definition*. The goal (roadmap §3.12/§6, v7.x) is to **feed** the policy
engines your ecosystem already runs rather than to compete with them as an
engine.

## The fidelity boundary (read this first)

The kit's 200+ evaluators are richer than any static Rego/CEL rule can express:
they clone the repo, parse workflows, and project scanner SARIF. A generated
rule **cannot** reproduce that, and pretending otherwise would be dishonest.

So the generated policy is an **integration shim, not a reimplementation**. The
rules check the kit's *own output*: you run `evaluate` to produce an
`evaluation-report.json`, feed that report to OPA/Kyverno as the engine input,
and the generated rules assert that every control the profile expects is
**present and in a passing state**. Every generated file carries this boundary
in its header comment.

```text
  repo  ──evaluate──▶  evaluation-report.json (reports/2.0)  ──▶  OPA / Kyverno
                                                                    ▲
                              export-policy ──generates──▶  policy.rego / policy.cel
```

## Usage

```text
# OPA / Conftest (Rego)
$ oss-policy-kit export-policy --profile github-level-1 --format rego --output policy.rego --validate

# Kyverno / cel-go (CEL)
$ oss-policy-kit export-policy --profile github-level-1 --format cel --output policy.cel --validate
```

| Flag | Default | Meaning |
|---|---|---|
| `--profile/-p` | *(required)* | Bundled profile id, or a path to a profile YAML. |
| `--format` | `rego` | `rego` (OPA/Conftest) or `cel` (Kyverno/cel-go). |
| `--output/-o` | `policy.<format>` | Where to write the rendered policy. |
| `--kit-root` | bundled data | Override the kit data root (`controls/` + `profiles/`). No short alias. |
| `--validate` | off | Lightweight syntactic check before writing (exit 1 on failure). |

Output is **deterministic and byte-stable**: controls are sorted by id, there is
no network access, and no timestamps are emitted. Re-running with the same
inputs produces the same file.

## What the generated Rego looks like

`--format rego` emits package `osspolicykit` with one `deny` rule per control
plus an aggregate `allow`:

```rego
package osspolicykit

import rego.v1

passing_states := {"PASS", "ATTESTED", "SELF_ATTESTED", "NOT_APPLICABLE"}

control_satisfied(id) if {
	some c in input.controls
	c.id == id
	c.state in passing_states
}

# GOV-SEC-001 — SECURITY.md present [assurance=deterministic]
deny contains msg if {
	not control_satisfied("GOV-SEC-001")
	msg := "GOV-SEC-001 not satisfied: control missing or not in a passing state in the supplied report"
}
# ... one deny rule per profile control ...

default allow := false

allow if count(deny) == 0
```

Wire it into Conftest or `opa eval`:

```text
$ oss-policy-kit evaluate --target . --profile github-level-1 --report-json-contract 2.0
$ opa eval -d policy.rego -i out/evaluation-report.json "data.osspolicykit.allow" --format raw
true
```

## What the generated CEL looks like

`--format cel` emits one boolean expression per control plus an aggregate
`all(...)`. Bind the CEL variable `report` to the `evaluation-report.json`:

```text
# GOV-SEC-001 — SECURITY.md present [assurance=deterministic]
report.controls.exists(c, c.id == "GOV-SEC-001" && c.state in ["PASS", "ATTESTED", "SELF_ATTESTED", "NOT_APPLICABLE"])

# ALL — every profile control present and in a passing state
["CI-DANGER-007", "..."].all(id, report.controls.exists(c, c.id == id && c.state in ["PASS", "ATTESTED", "SELF_ATTESTED", "NOT_APPLICABLE"]))
```

## Passing states (and how to tighten them)

The shim treats `PASS`, `ATTESTED`, `SELF_ATTESTED`, and `NOT_APPLICABLE` as
satisfied, mirroring the kit's own `--fail-on fail` posture: a deterministic
`FAIL` blocks; `UNKNOWN` (`manual-review-required`, `error`, `skipped`,
`waived`) is **not** satisfied. To gate more strictly (for example, to reject
`SELF_ATTESTED`), edit `passing_states` in the generated Rego or the
`[...]` list in the CEL before committing it to your pipeline.

## What `export-policy` will not do

- **Re-implement the evaluators.** The shim checks kit-produced input; it does
  not parse repos, workflows, or SARIF. That is the boundary, by design.
- **Validate engine semantics.** `--validate` is a lightweight syntactic check
  (package/header present, balanced blocks). Deep validation is the engine's
  job: run `opa check` / `conftest verify`, or compile the CEL in your host.
- **Add controls to the catalog.** It renders existing profile controls only.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Policy rendered (and, with `--validate`, passed the syntactic check). |
| 1 | `--validate` found a structural problem in the rendered output. |
| 2 | Usage error (unknown format, unknown profile, bad flags). |

## References

- ADR-035 — design rationale, fidelity boundary, alternatives considered
- [OPA / Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) · [Conftest](https://www.conftest.dev/) · [CEL](https://github.com/google/cel-spec) · [Kyverno](https://kyverno.io/)
- [`evidence-export.md`](evidence-export.md) — the report-consuming sibling (`export-evidence`)
- [`reports-contract-v2.0.md`](reports-contract-v2.0.md) — the report shape the generated policy checks
