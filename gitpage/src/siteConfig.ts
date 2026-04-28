/**
 * Override at build time for your fork:
 *   VITE_GITHUB_REPO_URL=https://github.com/org/repo
 *   VITE_BASE=/repo-name/   (GitHub Project Pages)
 */

/** Upstream repository (also used when env points at a legacy GitHub search URL). */
const CANONICAL_GITHUB_REPO =
  "https://github.com/lucashgrifoni/OSS-Security-Policy-as-Code-Starter-Kit" as const;

function isLegacyGithubSearchUrl(url: string): boolean {
  return url.includes("github.com/search");
}

function resolveGithubRepoUrl(fromEnv: string | undefined): string {
  const t = fromEnv?.trim();
  if (!t || isLegacyGithubSearchUrl(t)) return CANONICAL_GITHUB_REPO;
  return t;
}

function resolveDocsReadmeUrl(fromEnv: string | undefined, repoUrl: string): string {
  const t = fromEnv?.trim();
  if (!t || isLegacyGithubSearchUrl(t)) return `${repoUrl}/tree/main/docs`;
  return t;
}

const githubRepo = resolveGithubRepoUrl(import.meta.env.VITE_GITHUB_REPO_URL);

export const siteConfig = {
  name: "OSS Security Policy as Code Starter Kit",
  shortName: "OSS Policy Kit",
  githubRepo,
  /** Optional: override docs link (defaults to `.../tree/master/docs` on the resolved repo). */
  docsReadme: resolveDocsReadmeUrl(import.meta.env.VITE_DOCS_README_URL, githubRepo),
} as const;
