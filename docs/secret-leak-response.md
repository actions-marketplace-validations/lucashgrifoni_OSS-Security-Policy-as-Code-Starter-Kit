# Secret leak response runbook

Operator-facing playbook for handling sensitive data committed to a repository covered by this kit. Aligned with GitHub's official guidance on [removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

> **Read this once before you need it.** Rewriting Git history is irreversible from the perspective of every collaborator who already cloned the repository, and a leaked secret should be treated as compromised the moment it lands on a public hosting service.

## Decision rule

History rewrites do not "unleak" a secret. The cached blob can survive in:

- existing forks
- pull requests opened from the repo
- GitHub's REST and GraphQL APIs
- third-party mirrors, CI logs, and search indexes

Therefore the **first** action on any suspected exposure is **rotation**, not rewriting.

## Phase 1 - Contain (minutes)

1. **Rotate or revoke the credential** at the issuer (cloud IAM, package registry, OAuth app, signing key, etc.).
2. **Audit usage** of the credential. Pull access logs for the rotation window and look for unexpected callers.
3. **Freeze further pushes** to the affected branch by enabling branch protection or temporarily restricting push access.
4. **Decide ownership.** A single named operator runs the remaining phases. Coordinate with anyone who has the repository cloned locally.

## Phase 2 - Rewrite history

The repository must be a clean clone with no in-flight work; rewriting on top of unmerged branches will rewrite those too.

### Option A - `git filter-repo` (recommended by GitHub)

Install once:

```bash
pip install git-filter-repo
```

Remove a file that should never have been committed:

```bash
git clone --mirror https://github.com/<org>/<repo>.git
cd <repo>.git
git filter-repo --invert-paths --path path/to/secret-file
```

Replace a literal string (passwords, tokens) inline:

```bash
# expressions.txt - one rule per line, see git filter-repo --replace-text format
literal:AKIAEXAMPLE1234567890==>REDACTED
regex:ghp_[A-Za-z0-9]{36}==>REDACTED
```

```bash
git filter-repo --replace-text expressions.txt
```

### Option B - BFG Repo-Cleaner

Lighter-weight alternative when removing files or replacing fixed strings:

```bash
bfg --delete-files secret-file path/to/<repo>.git
bfg --replace-text expressions.txt path/to/<repo>.git
```

Then in either case:

```bash
git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push --force --all
git push --force --tags
```

> **Force-push warning.** This rewrites the published history. Every collaborator must reclone or hard-reset; a routine `git pull` will silently reintroduce the secret as a merge.

## Phase 3 - Purge GitHub-side caches

Force-pushing does not invalidate every server-side reference. After the rewrite:

1. **Close or rebase open pull requests** that touch the affected commits. PR diffs keep the old blob reachable.
2. **Delete stale branches and tags** that still point at rewritten commits.
3. **Open a GitHub Support request** asking for cache purge of the removed object SHAs. Provide the repository, the SHAs you want removed, and confirmation that the credential was rotated. This is the only supported path to flush the API cache.
4. **Track public forks** via the repository's network graph. Forks are independent repositories; a leaked secret in any of them remains exposed until the fork owner deletes or rewrites theirs.

## Phase 4 - Document and prevent

1. Capture the incident in your `incident-postmortem-author` track or equivalent. Record: what leaked, blast radius, time to rotate, time to rewrite, residual exposure (forks, PRs, mirrors).
2. Verify preventive controls are active on the repository:
   - Push protection for secret scanning (GitHub Advanced Security or public-repo free tier).
   - Pre-commit/local hooks that run `gitleaks` or equivalent before `git push`.
   - The `secret-scanning.yml` workflow shipped with this kit (`templates/workflows/secret-scanning.yml`).
3. Update or add a waiver under `waivers/` only if the residual exposure is a known, accepted risk - never as a substitute for rotation.

## Operator checklist

- [ ] Credential rotated at the issuer.
- [ ] Usage audit completed; no abuse detected (or escalated if detected).
- [ ] Branch protection enabled while rewriting.
- [ ] Mirror clone created; `git filter-repo` or BFG run against it.
- [ ] Reflog expired and GC run.
- [ ] Force-push completed for branches and tags.
- [ ] Open PRs touching rewritten commits closed or rebased.
- [ ] Stale branches/tags pointing at old commits deleted.
- [ ] GitHub Support ticket filed for cache purge.
- [ ] Forks reviewed; owners notified where applicable.
- [ ] Postmortem written.
- [ ] Preventive controls verified or added.

## See also

- [SECURITY.md](../SECURITY.md) - reporting a vulnerability
- [templates/workflows/secret-scanning.yml](../templates/workflows/secret-scanning.yml) - preventive scan
- GitHub docs: [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- GitHub docs: [About secret scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
