import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Menu, X } from "lucide-react";
import { navSections } from "../../navSections";
import { siteConfig } from "../../siteConfig";
import { cn } from "../../lib/cn";

function scrollToId(id: string) {
  const el = document.getElementById(id);
  el?.scrollIntoView({ behavior: "smooth", block: "start" });
}

export function SiteHeader() {
  const [open, setOpen] = useState(false);
  const reduce = useReducedMotion();

  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-white/5 bg-ink/75 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        <a
          href="#hero"
          className="group flex items-center gap-2 font-semibold tracking-tight text-mist"
          onClick={(e) => {
            e.preventDefault();
            scrollToId("hero");
          }}
        >
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-signal/40 bg-signal/10 font-mono text-xs text-signal shadow-glow-sm">
            OSS
          </span>
          <span className="hidden sm:inline">{siteConfig.shortName}</span>
        </a>

        <nav
          className="hidden min-w-0 flex-1 flex-nowrap items-center justify-end gap-0.5 overflow-x-auto lg:flex lg:[scrollbar-width:none] lg:[-ms-overflow-style:none] lg:[&::-webkit-scrollbar]:hidden"
          aria-label="Primary"
        >
          {navSections.slice(1).map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => scrollToId(s.id)}
              className="shrink-0 whitespace-nowrap rounded-lg px-2 py-2 text-xs text-slate transition hover:bg-white/5 hover:text-mist 2xl:text-sm 2xl:px-2.5"
            >
              {s.label}
            </button>
          ))}
          <a
            href={siteConfig.githubRepo}
            target="_blank"
            rel="noreferrer noopener"
            className="ml-1 shrink-0 whitespace-nowrap rounded-lg border border-signal/40 bg-signal/10 px-2.5 py-2 text-xs font-medium text-signal shadow-glow-sm transition hover:bg-signal/20 2xl:px-3 2xl:text-sm"
          >
            GitHub
          </a>
        </nav>

        <button
          type="button"
          className="inline-flex items-center justify-center rounded-lg border border-white/10 p-2 text-mist md:hidden"
          aria-expanded={open}
          aria-controls="mobile-nav"
          onClick={() => setOpen((v) => !v)}
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          <span className="sr-only">Menu</span>
        </button>
      </div>

      <AnimatePresence>
        {open ? (
          <motion.div
            id="mobile-nav"
            initial={reduce ? false : { height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={reduce ? undefined : { height: 0, opacity: 0 }}
            className="border-t border-white/5 bg-ink/95 md:hidden"
          >
            <div className="flex max-h-[70vh] flex-col gap-1 overflow-y-auto px-4 py-4">
              {navSections.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  className={cn(
                    "rounded-lg px-3 py-3 text-left text-sm text-slate hover:bg-white/5 hover:text-mist",
                  )}
                  onClick={() => {
                    setOpen(false);
                    scrollToId(s.id);
                  }}
                >
                  {s.label}
                </button>
              ))}
              <a
                href={siteConfig.githubRepo}
                target="_blank"
                rel="noreferrer noopener"
                className="mt-2 rounded-lg border border-signal/40 px-3 py-3 text-center text-sm font-medium text-signal"
              >
                View on GitHub
              </a>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </header>
  );
}
