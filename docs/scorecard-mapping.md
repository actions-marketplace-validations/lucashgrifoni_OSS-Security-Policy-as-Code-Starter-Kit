# OpenSSF Scorecard mapping notes

[OpenSSF Scorecard](https://securityscorecards.dev/) provides automated signals for many repositories. This kit is **complementary**, not a replacement.

## How Scorecard is used in `v0.1.0`

Optional input:

```bash
python -m oss_policy_kit evaluate --target ./repo --profile github-level-1 --scorecard-json ./scorecard.json
# or: python -m oss_policy_kit --target ./repo --profile github-level-1 --scorecard-json ./scorecard.json
```

The JSON adapter accepts a few common shapes, including a top-level `checks` list or a nested `scorecard.checks` list.

## Current supplemental behavior

- `SEC-CODEQL-010` may `pass` when Scorecard includes checks whose names suggest static analysis posture (for example `Code-QL`), **only if** local workflows do not already prove CodeQL.

**Confidence** for supplemental passes is intentionally lower than in-repo workflow detection.

## What Scorecard does not prove

Scorecard cannot, by itself, establish:

- full OSPS alignment
- that your threat model is adequate
- that your release process is safe end-to-end

Treat Scorecard exports as **additional evidence**, not a final verdict.
