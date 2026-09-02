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

## Posture, and what the Scorecard does not measure

The repository publishes an [OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit). Some of its checks score zero or near zero and will stay that way; they are listed here so the score is read correctly rather than as an unaddressed defect.

| Check | Score | Why it is where it is |
|---|---|---|
| Code-Review | 0 | One maintainer. A pull request cannot be reviewed by its author, and there is nobody else. Every change still passes the 13 required status checks, a required commit signature, and a linear-history rule before it reaches `master`. |
| Contributors | 0 | The check counts contributors from several organizations. This project has one. |
| Branch-Protection | 3 | The ruleset requires signatures, 13 status checks, linear history and no force-push. It does not require a review (see above) and it allows the repository owner to bypass — which is how a solo maintainer merges at all. |

What the score *does* reflect: SAST, signed releases, pinned dependencies, token permissions, dangerous-workflow analysis, fuzzing, and a vulnerability-free dependency tree are each measured and each at or near the maximum. A drop in any of those is a regression worth reporting.

### Findings that are open on purpose

Two classes of alert stay open in code scanning. Both are accurate about what they measure and neither describes a defect that can be closed here.

**Pinned-Dependencies on the CI dev install.** The workflow installs the project's `dev` extra from PyPI without hashes. A lock for it would have to be regenerated inside every Dependabot pull request that bumps a dev tool, and a lock that drifts from `pyproject.toml` fails silently rather than loudly: CI would test one version of ruff or mypy while the project declares another, and a green run would stop meaning what it says. That is a worse outcome than the finding, which covers tools that run only in CI, in a job that holds no secrets. Everything shipped to a user *is* hash-pinned — the container image installs from `.github/requirements/`, which Dependabot watches. The check also flags the image's final `pip install .`, which installs the checked-out tree itself and has no hash to carry.

**Base-image CVEs in `pip`.** A job scans the base image pinned by digest in the `Dockerfile` and reports six CVEs in the `pip 25.0.1` that Debian's Python image ships. The published image does not contain them: the runtime stage uninstalls pip from both interpreters, and a scan of the built image reports no fixable vulnerability at any severity. Bumping the digest does not clear them either, because the current upstream image ships the same pip. They describe the image this project builds *from*, which is worth knowing, not the image it publishes.

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
