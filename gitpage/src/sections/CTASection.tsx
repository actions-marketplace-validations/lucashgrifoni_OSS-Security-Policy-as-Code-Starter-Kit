import { ArrowRight, BookOpen } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { siteConfig } from "../siteConfig";

export function CTASection() {
  const reduce = useReducedMotion();

  return (
    <section id="cta" className="relative scroll-mt-24 py-24 md:scroll-mt-28 md:py-32">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <motion.div
          initial={reduce ? false : { opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.65 }}
          className="relative overflow-hidden rounded-[2rem] border border-signal/30 bg-gradient-to-br from-signal/20 via-ink to-ink p-10 shadow-glow md:p-16"
        >
          <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-signal/25 blur-[100px]" />
          <div className="pointer-events-none absolute -bottom-28 -left-20 h-80 w-80 rounded-full bg-slate/30 blur-[110px]" />

          <div className="relative max-w-3xl">
            <p className="font-mono text-xs uppercase tracking-[0.3em] text-mist/80">Next step</p>
            <h2 className="mt-4 text-3xl font-semibold tracking-tight text-mist md:text-5xl">
              Run the self-check, compare the fixtures, and use the first report as your backlog.
            </h2>
            <p className="mt-6 text-base leading-relaxed text-slate md:text-lg">
              Start with `python -m oss_policy_kit profiles`, then evaluate your clone with
              `github-level-1` or the recommended profile. If you need a fast demo, the repository
              already ships hardened and vulnerable examples that make the output easy to explain.
            </p>
            <div className="mt-10 flex flex-wrap gap-4">
              <a
                href={siteConfig.githubRepo}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-2 rounded-xl bg-signal px-6 py-3 text-sm font-semibold text-ink shadow-glow transition hover:bg-signal/90 hover:shadow-[0_0_40px_-6px_rgba(8,185,139,0.55)]"
              >
                Open repository
                <ArrowRight className="h-4 w-4" />
              </a>
              <a
                href={siteConfig.docsReadme}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-flex items-center gap-2 rounded-xl border border-white/20 px-6 py-3 text-sm font-medium text-mist transition hover:border-signal/50 hover:bg-white/5"
              >
                <BookOpen className="h-4 w-4" />
                Open docs
              </a>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
