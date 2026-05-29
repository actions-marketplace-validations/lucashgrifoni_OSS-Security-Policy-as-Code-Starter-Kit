# OpenSSF Security Insights ingestion (`ingest-insights`)

> **Available since v6.7.0.** The `ingest-insights` subcommand reads a target's
> Security Insights file and reports it. This page is the adopter guide and the
> consumer-side companion to [`insights-emission.md`](insights-emission.md).

`emit-insights` *produces* an OpenSSF Security Insights 1.0 document; `ingest-insights`
*consumes* one that a repository already publishes. It closes the emit↔ingest asymmetry
the v7.x interoperability horizon calls out (Scorecard v6, CLOMonitor, and LFX Insights
all ingest Security Insights — the kit now reads it too). See ADR-032 for the rationale.

## What it does

```text
$ oss-policy-kit ingest-insights --target . --format json
```

1. **Discovers** the file under `--target` (or use `--input <path>` to point at one
   explicitly). Lookup order: `SECURITY-INSIGHTS.yml`/`.yaml` at the repo root, then
   `.github/`, then the kit's own lowercase `security-insights.yml`/`.yaml` (root and
   `.github/`), then `docs/SECURITY-INSIGHTS.yml`.
2. **Parses** the YAML (size-bounded, UTF-8).
3. **Structurally validates** it against the OpenSSF Security Insights 1.0 shape the kit
   knows (`header.schema-version`, `header.last-updated`, `project-lifecycle.status`).
4. **Reports** the recognized signals as `human` text (default) or `--format json`.

## The honesty model: self-reported, not verified

A `SECURITY-INSIGHTS.yml` is **authored by the project itself**. It is a self-assertion,
not independent evidence. `ingest-insights` reflects this everywhere:

- Output always carries `provenance: self-reported`.
- The human summary prints a one-line caveat that the kit did **not** verify the claims.
- **It does not change any `evaluate` gate.** No control's PASS/FAIL/UNKNOWN verdict
  changes because a Security Insights file exists. Wiring these fields into controls as a
  `self-attested` evidence source is a deliberate, separate increment (see ADR-032) that
  needs an explicit per-control mapping; it is intentionally **not** part of this command.

This keeps the kit's assurance-honesty guard-rail intact: self-reported stays self-reported.

## Recognized signals

| Signal (JSON key) | Source field in Security Insights 1.0 |
|---|---|
| `project_lifecycle_status` | `project-lifecycle.status` |
| `accepts_vulnerability_reports` | `vulnerability-reporting.accepts-vulnerability-reports` |
| `security_policy_url` | `vulnerability-reporting.security-policy` |
| `security_contacts` | `security-contacts[].value` + `vulnerability-reporting.email-contact` |
| `accepts_pull_requests` | `contribution-policy.accepts-pull-requests` |
| `has_dependency_automation_policy` | presence of a `dependencies` block |
| `distribution_points` | `distribution-points[]` |

Absent fields are reported as `null` / `false` / `[]` — never inferred.

## JSON output shape

```json
{
  "tool": "oss-policy-kit ingest-insights",
  "kit_version": "6.7.0",
  "schema_version_supported": "1.0.0",
  "found": true,
  "input_path": "SECURITY-INSIGHTS.yml",
  "valid": true,
  "provenance": "self-reported",
  "declared_schema_version": "1.0.0",
  "validation_errors": [],
  "validation_warnings": [],
  "signals": {
    "project_lifecycle_status": "active",
    "accepts_vulnerability_reports": true,
    "security_policy_url": "https://github.com/org/repo/blob/main/SECURITY.md",
    "security_contacts": ["security@example.com"],
    "accepts_pull_requests": true,
    "has_dependency_automation_policy": true,
    "distribution_points": []
  }
}
```

A declared `schema-version` other than the supported `1.0.0` is reported as a
**warning** (a newer upstream file is still summarized), not a validation error.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | A valid file was found and summarized, **or** no file was found (informational — nothing to ingest). |
| 1 | A file was found but failed structural validation (missing required fields, not a YAML object, or unparseable). |
| 2 | Usage error (an explicit `--input` path does not exist; `--target` is not a directory; bad `--format`; oversized file). |
| 3 | Unexpected internal error. |

## What it will not do

- Change, gate, or influence `evaluate`. Pair the two only by reading both outputs yourself.
- Treat self-reported claims as verified evidence.
- Fetch anything or mutate the target. Clone-local, read-only.
- Validate the *contents* beyond the structural 1.0 shape. Run a dedicated consumer
  (Scorecard v6, CLOMonitor) to confirm upstream interpretation.

## References

- [OpenSSF Security Insights spec](https://security-insights.openssf.org/) + [GitHub repo](https://github.com/ossf/security-insights)
- ADR-032 — design rationale for ingestion and the assurance fence
- ADR-011 (`emit-insights`) — the producer side
- [`insights-emission.md`](insights-emission.md) — companion producer guide
