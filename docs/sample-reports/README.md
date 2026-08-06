# Sample Reports

These reports are generated from the bundled example repositories with `github-level-1`.
They are meant for quick inspection in GitHub without running the CLI first.

They are on the `reports/2.0` contract — the only contract the kit emits or reads since
v9.0.0 — and are regenerated whenever the report shape changes, so what is checked in here
is what the current CLI actually writes. Both runs are stamped with
`SOURCE_DATE_EPOCH=1785974400` (2026-08-06T00:00:00Z), which the kit honors for every
outcome-affecting clock read; export it before regenerating and the output is byte-identical.

Evidence references are redacted to their final component (`<redacted-absolute>/SECURITY.md`).
That is the same redaction any adopter gets by default: a shareable report never carries the
directory chain of the machine it was produced on.

## Hardened Example

- [Markdown report](hardened/evaluation-report.md)
- [JSON report](hardened/evaluation-report.json)

Command:

```bash
python -m oss_policy_kit evaluate \
  --target ./examples/hardened-repo \
  --profile github-level-1 \
  --output-dir ./docs/sample-reports/hardened \
  --summary-only
```

Expected shape: `{"PASS": 14}` — 14 of 14 controls satisfied.

## Vulnerable Example

- [Markdown report](vulnerable/evaluation-report.md)
- [JSON report](vulnerable/evaluation-report.json)

Command:

```bash
python -m oss_policy_kit evaluate \
  --target ./examples/vulnerable-repo \
  --profile github-level-1 \
  --output-dir ./docs/sample-reports/vulnerable \
  --summary-only
```

Expected shape: `{"FAIL": 11, "PASS": 2, "UNKNOWN": 1}`, with remediation text on each failing
control. This run intentionally does not pass `--fail-on fail`, so the sample report files are
still written instead of the gate stopping the run at exit 1.
