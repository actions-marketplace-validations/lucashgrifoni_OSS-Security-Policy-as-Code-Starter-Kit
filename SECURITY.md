# Security policy

## Supported versions

Security fixes are generally applied to the latest supported default branch. Release tags may exist for packaging and changelog traceability, but this repository is maintained primarily on the default branch.

## Reporting a vulnerability

### Preferred channel

Use GitHub private vulnerability reporting for this repository when it is enabled:

- Repository: `https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit`
- Entry point: **Security** tab -> **Report a vulnerability**

If private vulnerability reporting is not enabled yet, contact the maintainer through a private channel you trust before disclosing technical details publicly.

Do not open a public issue for an undisclosed vulnerability.

### What to include

Include, when possible:

- a concise description of the issue
- steps to reproduce
- impact notes
- affected versions, commits, or files
- proof-of-concept details only when necessary to reproduce safely

### Response expectations

This is a volunteer-maintained OSS project. Reports will be reviewed in a reasonable timeframe, but no formal SLA is guaranteed.

### Coordinated disclosure

Please allow reasonable time for validation and remediation before public disclosure, unless immediate disclosure is required by law or the issue is already being actively exploited in public.

## Sensitive data exposure

If a credential, key, or other sensitive value is committed to this repository, follow [docs/secret-leak-response.md](docs/secret-leak-response.md). Rotate the credential at the issuer first; rewriting Git history does not invalidate a secret already published.

Preventive scanning is provided by [templates/workflows/secret-scanning.yml](templates/workflows/secret-scanning.yml), which downstream consumers of this kit can copy into `.github/workflows/`.

## Scope

Reports should target this repository and its distributed artifacts:

- the Python CLI
- bundled policy data
- schemas
- templates
- documentation and workflow material that directly affects the distributed project

## Out of scope examples

- vulnerabilities in downstream repositories that only consume this kit
- generic security questions unrelated to this codebase
- issues in third-party services not operated by this repository
