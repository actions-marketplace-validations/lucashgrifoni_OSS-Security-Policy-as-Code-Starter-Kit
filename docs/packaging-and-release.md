# Packaging and release

This document describes how to install, build, validate, and distribute the `oss-policy-kit` package.

## Supported distribution channels

| Channel | Audience | Notes |
| --- | --- | --- |
| PyPI package (`oss-policy-kit`) | end users and CI consumers | primary install channel: `python -m pip install oss-policy-kit` |
| Wheel or sdist attached to a GitHub Release | end users and CI consumers | alternative install path when you pin release assets directly |
| Git clone + editable install | contributors and maintainers | `python -m pip install -e ".[dev]"` |

## What gets published

- `sdist` (`.tar.gz`)
- `wheel` (`.whl`)
- CycloneDX SBOM JSON as a release/documentation artifact (`artifacts/sbom.cyclonedx.json`)

Policy data is packaged only from `src/oss_policy_kit/data/` using explicit YAML and JSON globs. Packaging intentionally excludes cache and bytecode files.

## Prerequisites

- Python 3.12+
- current enough `pip` for PEP 517 builds

Developer install:

```bash
python -m pip install -e ".[dev]"
```

Minimal one-off build tooling:

```bash
python -m pip install --upgrade pip build twine
```

## Dependency and supply-chain posture

Runtime dependencies live under `[project].dependencies` in `pyproject.toml`.

Principles:

- keep runtime dependencies minimal
- prefer actively maintained packages with clear licenses
- use conservative version ranges
- keep dev-only tooling under `[project.optional-dependencies].dev`

Security-related checks already used by this repository:

- dependency review on pull requests
- `pip-audit` in the security workflow
- SBOM generation in the package workflow

Useful local release-time check:

```bash
pip install pip-audit
pip-audit
```

## Local build and validation

Clean stale artifacts first:

```bash
rm -rf dist build .consumer-smoke-venv src/*.egg-info
```

Windows PowerShell:

```powershell
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue dist, build, .consumer-smoke-venv
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue src\oss_policy_kit.egg-info
```

Build and validate:

```bash
python -m build
python scripts/twine_check_dist.py
```

The helper resolves the sdist and wheel that match the current `pyproject.toml` version and runs `twine check` with **explicit paths**, so it behaves correctly on **Windows PowerShell** (where `dist/*` is not expanded the same way as on POSIX shells).

POSIX shell (explicit globs, no helper):

```bash
python -m build
python -m twine check dist/oss_policy_kit-*.tar.gz dist/oss_policy_kit-*.whl
```

Windows PowerShell (explicit files after `build`; adjust the version segment if needed):

```powershell
python -m build
python -m twine check @(
    (Get-ChildItem -Path dist -Filter "oss_policy_kit-*.tar.gz" -File).FullName
    (Get-ChildItem -Path dist -Filter "oss_policy_kit-*.whl" -File).FullName
)
```

## Install the wheel in a clean environment

```bash
python -m venv .venv-release
# Windows: .venv-release\Scripts\activate
# Unix: source .venv-release/bin/activate
python -m pip install dist/*.whl
python -m oss_policy_kit --help
python -m oss_policy_kit evaluate --help
```

Windows PowerShell:

```powershell
python -m venv .venv-release
.\.venv-release\Scripts\Activate.ps1
python -m pip install (Get-ChildItem dist\oss_policy_kit-*.whl | Sort-Object Name | Select-Object -Last 1)
python -m oss_policy_kit --help
```

## Official consumer smoke

The repository ships `scripts/consumer_smoke.py` for a reproducible end-user style smoke run.

What it does:

1. creates a temporary isolated venv
2. installs the wheel that matches the current `pyproject.toml` version from `dist/`
3. runs `--version`, `--help`, `evaluate --help`, self-check, hardened/vulnerable examples, `--fail-on`, waivers, and `--kit-root`
4. writes `out/consumer-smoke-summary.json` and `out/consumer-smoke-summary.md`

It fails fast when the current-version wheel is missing or ambiguous.

Run it after `python -m build`:

```bash
python scripts/consumer_smoke.py --repo-root .
```

Windows PowerShell:

```powershell
python .\scripts\consumer_smoke.py --repo-root .
```

Use `--keep-venv` only when debugging.

## CI validation

The package workflow in `.github/workflows/github-ci-cd.yml` is expected to:

1. clean build artifacts
2. run `python -m build`
3. run `python scripts/twine_check_dist.py` (twine with explicit artifact paths)
4. generate a CycloneDX SBOM
5. smoke-install the wheel and run CLI help commands

This workflow validates artifacts. It does not publish to PyPI.
PyPI publication is an active channel for consumers, but the upload step is handled
outside this default CI validation workflow set.

## Versioning and changelog discipline

Before tagging a release:

1. align version in `pyproject.toml` and `src/oss_policy_kit/__init__.py`
2. update user-facing docs if install or compatibility guidance changed
3. move `CHANGELOG.md` from `Unreleased` into a dated release section
4. clean `dist/`, `build/`, and `.consumer-smoke-venv/` before running packaging validation

### `v4.0.0` tag note

The `4.0.0` release is consolidated in `pyproject.toml` and `CHANGELOG.md`, but creating and pushing the `v4.0.0` git tag is a **manual maintainer action** and is intentionally **not** part of the docs/UX round that introduced this subsection. The suggested command is:

```bash
git tag -a v4.0.0 -m "oss-policy-kit 4.0.0"
# or, if the repo policy requires signed tags
git tag -s v4.0.0 -m "oss-policy-kit 4.0.0"
```

Push the tag separately once the maintainer has reviewed the consolidated history.

## Private Maintainer Notes

Maintainer-private planning notes, prompts, exploratory audits, and local validation scratchpads must stay outside the
public repository tree. Keep them in a private workspace or private repository and copy only durable, public-facing
outcomes into `docs/`, `CHANGELOG.md`, tests, or release notes.

Before a public release, verify:

```bash
git ls-files private-notes
```

The command should return no tracked files.

## PyPI

PyPI is an active distribution channel for this project.

Consumer install examples:

```bash
python -m pip install oss-policy-kit
python -m pip install oss-policy-kit==<version>
python -m oss_policy_kit --version
```

Keep the distinction explicit:

- **Distribution channels for users:** PyPI (primary), GitHub Release wheel/sdist (alternative).
- **Internal release process:** build, validate (`twine check` and consumer smoke), test on TestPyPI first, then publish/upload through maintainer-controlled release steps.

If a release is available on GitHub before PyPI propagation completes, GitHub Release artifacts remain a valid temporary install path for consumers who need that exact build immediately.

## `publish-pypi.yml` workflow

`.github/workflows/publish-pypi.yml`:

- Pins third-party GitHub Actions to immutable commit SHAs (with `# vX.Y` comments for humans).
- **`workflow_dispatch`** with **`target=testpypi`** publishes to TestPyPI first (**recommended** gate before wider promotion).
- Production PyPI publication runs from **`publish-pypi`** only on **`push`** of version tags **`v*`** (OIDC to `pypi`).
