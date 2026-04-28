# gitpage - optional GitHub Pages site

This directory contains the optional front-end site for the project. It is a separate Vite + React + TypeScript application used for public presentation. It is **not** part of the Python package published as `oss-policy-kit`.

## What it is for

- project website and public landing page
- product positioning and onboarding content
- GitHub Pages deployment from `gitpage/`

## What it is not

- not part of the Python wheel or sdist
- not required to use the CLI
- not required for the Python test suite

## Expected toolchain

- **Node.js**: align with `.github/workflows/deploy-github-pages.yml` (currently Node 20 LTS)
- **npm**: use `npm ci` with the committed `package-lock.json`

## Local usage

From `gitpage/`:

```bash
npm ci
npm run dev
```

Production build:

```bash
npm run build
```

The build output is written to `gitpage/dist/`.

## CI behavior

The site is deployed by `.github/workflows/deploy-github-pages.yml`.

Important boundaries:

- Python quality, typing, tests, packaging, and security checks run in the repository root workflows
- the Pages workflow runs only for `gitpage/**` and the Pages workflow file itself
- the Python package does not depend on Node tooling

## Windows troubleshooting

Local Windows environments are more likely than CI Linux to hit file-lock and permission problems during `npm ci`.

### Common symptoms

- `EPERM`
- `EACCES`
- `operation not permitted`
- failed rename or extract under `node_modules`

### Common causes

- antivirus or Defender locking files under `node_modules`
- IDEs, terminals, or `npm run dev` keeping handles open
- synced folders such as OneDrive or network-backed directories

### Recovery steps

1. Stop `npm run dev` and close the IDE for `gitpage/`.
2. Delete `gitpage/node_modules`.
3. Run `npm ci` again from a normal user shell.
4. Only if your environment policy allows it, temporarily exclude `gitpage/node_modules` from antivirus scanning.
5. If the problem persists, retry in WSL2 or rely on the GitHub Actions Pages workflow as the build reference.

## Source of truth

For release confidence, the authoritative answer to "does the site build?" is the GitHub Pages workflow on GitHub Actions.
