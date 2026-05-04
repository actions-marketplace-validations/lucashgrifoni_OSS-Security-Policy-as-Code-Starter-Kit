# Release readiness

This is the maintainer checklist for patch releases, public launch, and routine repository operations.

Keep detailed launch evidence, private planning notes, and internal traceability packs outside the public repository. This page is the public operational checklist.

## Repository contents

- [ ] `LICENSE` is present and correct
- [ ] `NOTICE` contains attribution if required
- [ ] `README.md` explains what the project is and is not
- [ ] `SECURITY.md` matches the actual vulnerability reporting path
- [ ] `CHANGELOG.md` reflects the intended release
- [ ] `pyproject.toml` version matches `src/oss_policy_kit/__init__.py` (for example `4.0.0` on the current release line)

## Quality gates

- [ ] `python -m pytest -q`
- [ ] `python -m ruff check src tests`
- [ ] `python -m mypy src/oss_policy_kit --strict`

## Packaging gates

- [ ] clean `dist/`, `build/`, and `.consumer-smoke-venv/` before validating artifacts
- [ ] `python -m build`
- [ ] `python scripts/twine_check_dist.py` (preferred; resolves the current package version and avoids PowerShell `dist/*` glob issues)
- [ ] `python scripts/consumer_smoke.py --repo-root .`
- [ ] `pip install cyclonedx-bom && python -m cyclonedx_py environment --of JSON -o artifacts/sbom.cyclonedx.json` produces a valid SBOM JSON file
- [ ] SBOM (`artifacts/sbom.cyclonedx.json`) published as a dedicated GitHub Actions artifact or release asset alongside the package distributions
- [ ] run the `publish-pypi.yml` workflow with `workflow_dispatch` and `target=testpypi` before the official PyPI publish (**third-party Actions in this workflow are pinned by full commit SHA** — rotate intentionally)

See `docs/packaging-and-release.md` for exact commands.

## Product smoke

- [ ] `python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/vulnerable`
- [ ] `python -m oss_policy_kit evaluate --target ./examples/hardened-repo --profile github-level-1 --output-dir ./out/hardened`
- [ ] `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck`
- [ ] `python -m oss_policy_kit evaluate --target ./examples/vulnerable-repo --profile github-level-1 --output-dir ./out/gate --fail-on fail` exits with code `1`
- [ ] optional parser smoke: `python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/summary --summary-only --format json`
- [ ] `python -m oss_policy_kit profiles` and `python -m oss_policy_kit profiles --format json`
- [ ] optional: `python -m oss_policy_kit recommend-profile --target ./examples/hardened-repo`
- [ ] optional: `python -m oss_policy_kit scaffold-evidence --target . --platform github` in a throwaway directory, then delete artifacts

## Claims hygiene

- [ ] no certification or compliance claims in docs
- [ ] automation limits are visible in `README.md` and `docs/architecture.md`

## What "green" means

- `github-level-1` with 14 `pass` means the local repository posture matches this kit's starter baseline well
- `github-release-hardening-1` with `pass` plus `manual-review-required` or `self-attested` is normal when branch protection remains a platform-side concern

That is intentional honesty, not a defect.

## Patch release routine

- [ ] working tree clean of accidental artifacts
- [ ] no secrets or tokens in tracked files
- [ ] if `gitpage/` changed, run `npm ci` and `npm run build`
- [ ] if templates changed, spot-check the recommended adoption path
- [ ] update release notes in `CHANGELOG.md`

## GitHub settings before public launch

Complete these manually on GitHub:

- [ ] `Settings -> General`: confirm the default branch and repository description
- [ ] `Settings -> Code security`: enable private vulnerability reporting
- [ ] `Settings -> Branches` or `Rules -> Rulesets`: protect the default branch
- [ ] `Settings -> Branches / Rulesets -> Required status checks`: require the exact job names you rely on
- [ ] `Settings -> Actions`: confirm Actions are enabled and not blocked by policy
- [ ] confirm default branch runs are green after merge

Typical merge-blocking jobs for this repository:

- `GitHub CI/CD`: quality and package jobs
- `Security CI/CD`: dependency review, CodeQL, and security jobs you choose to block on

`Deploy GitHub Pages` is usually a delivery workflow, not a merge blocker for the Python package.

## Workflow pinning and routine operations

Third-party GitHub Actions should stay pinned to full commit SHAs.

When rotating SHAs:

1. read upstream release notes
2. update the workflow YAML
3. validate locally with a self-check
4. confirm Actions still pass after push

If a workflow or job name changes, update branch protection or rulesets to match the new name shown in GitHub Actions.

## gitpage operations

The site under `gitpage/` is optional.

Operational rules:

- run `npm ci` after lockfile changes
- delete `gitpage/node_modules` if you suspect corruption or Windows file-lock issues
- treat the GitHub Pages workflow as the build source of truth when local Windows behavior is noisy

## Final public launch question

You are ready to make the repository public when all of these are true:

- the quality, packaging, and smoke gates are green
- the README and docs describe the project honestly
- local-only or internal planning files are gone
- GitHub security and repository settings are aligned with the public launch you want
