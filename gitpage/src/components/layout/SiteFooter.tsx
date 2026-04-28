import { siteConfig } from "../../siteConfig";

export function SiteFooter() {
  return (
    <footer className="border-t border-white/10 py-12 text-sm text-slate">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <p className="max-w-xl leading-relaxed">
          Python package and GitHub Pages site for local OSS security evaluation. Apache-2.0.
          Evidence first, explicit limits, and no certification theater.
        </p>
        <div className="flex flex-wrap gap-4 font-mono text-xs text-steel">
          <a
            className="hover:text-signal"
            href={siteConfig.githubRepo}
            target="_blank"
            rel="noreferrer noopener"
          >
            Repository
          </a>
          <span aria-hidden>|</span>
          <a
            className="hover:text-signal"
            href={siteConfig.docsReadme}
            target="_blank"
            rel="noreferrer noopener"
          >
            Docs
          </a>
          <span aria-hidden>|</span>
          <a className="hover:text-signal" href="#quickstart">
            Quickstart
          </a>
        </div>
      </div>
    </footer>
  );
}
