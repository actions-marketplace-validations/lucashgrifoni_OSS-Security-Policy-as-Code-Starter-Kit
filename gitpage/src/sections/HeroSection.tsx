import { useRef } from "react";
import { motion, useReducedMotion, useScroll, useTransform } from "framer-motion";
import { ArrowRight, ChevronDown, Layers, Shield } from "lucide-react";
import { Reveal } from "../components/effects/Reveal";
import { siteConfig } from "../siteConfig";

const keywords = [
  "Local clone evaluation",
  "Versioned profiles",
  "Markdown + JSON reports",
  "Waivers",
  "Evidence scaffolding",
  "Scorecard JSON",
  "CI gates",
] as const;

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function JsonPanelDecor() {
  return (
    <div className="hero-json-panel-surface flex h-full min-h-[14rem] w-full max-w-full flex-col overflow-hidden rounded-2xl border border-white/[0.09] backdrop-blur-xl">
      <div className="relative flex min-h-0 flex-1 flex-col gap-3 p-5 pt-6 font-mono text-[10px] leading-relaxed">
        <div className="flex items-center gap-2 border-b border-white/[0.06] pb-2.5 text-signal">
          <Shield className="h-4 w-4 shrink-0 opacity-90" strokeWidth={2} aria-hidden />
          <span className="tracking-tight">evaluation-report.json</span>
        </div>
        <div className="space-y-1.5 text-slate/90">
          <p>
            <span className="text-steel">{"{ "}</span>
            <span className="text-signal/95">&quot;schema_version&quot;</span>
            <span className="text-steel">: </span>
            <span className="text-mist/95">&quot;oss-policy-kit/report/v1&quot;</span>
            <span className="text-steel">,</span>
          </p>
          <p className="pl-2">
            <span className="text-signal/95">&quot;profile&quot;</span>
            <span className="text-steel">: </span>
            <span className="text-mist/95">&quot;github-level-1&quot;</span>
            <span className="text-steel">,</span>
          </p>
          <p className="pl-2">
            <span className="text-signal/95">&quot;summary&quot;</span>
            <span className="text-steel">: {"{ "}</span>
            <span className="text-signal/95">&quot;pass&quot;</span>
            <span className="text-steel">: </span>
            <span className="text-mist">12</span>
            <span className="text-steel">, </span>
            <span className="text-signal/95">&quot;fail&quot;</span>
            <span className="text-steel">: </span>
            <span className="text-mist">2</span>
            <span className="text-steel">, </span>
            <span className="text-signal/95">&quot;manual-review-required&quot;</span>
            <span className="text-steel">: </span>
            <span className="text-mist">2</span>
            <span className="text-steel"> {"}"}</span>
          </p>
          <p className="pl-2">
            <span className="text-signal/95">&quot;outputs&quot;</span>
            <span className="text-steel">: [ </span>
            <span className="text-mist/95">&quot;evaluation-report.json&quot;</span>
            <span className="text-steel">, </span>
            <span className="text-mist/95">&quot;evaluation-report.md&quot;</span>
            <span className="text-steel"> ] {"}"}</span>
          </p>
        </div>
        <div className="mt-auto flex items-center gap-2 border-t border-white/[0.06] pt-3 text-[9px] text-steel">
          <Layers className="h-3.5 w-3.5 shrink-0 opacity-80" aria-hidden />
          <span className="tracking-wide">explicit states + evidence + remediation</span>
        </div>
      </div>
    </div>
  );
}

export function HeroSection() {
  const ref = useRef<HTMLElement>(null);
  const reduce = useReducedMotion();
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end start"],
  });
  const y1 = useTransform(scrollYProgress, [0, 1], [0, reduce ? 0 : 72]);
  const y2 = useTransform(scrollYProgress, [0, 1], [0, reduce ? 0 : 40]);
  const op = useTransform(scrollYProgress, [0, 0.55], [1, reduce ? 1 : 0.2]);

  return (
    <section
      ref={ref}
      id="hero"
      className="relative flex min-h-[100dvh] flex-col justify-center overflow-x-hidden overflow-y-visible pt-20"
    >
      <div className="hero-section-ambient pointer-events-none absolute inset-0 z-0" aria-hidden />

      <motion.div
        style={{ opacity: op, y: y1 }}
        className="hero-gutter-signal-card pointer-events-none absolute top-[20%] z-[1] hidden h-48 w-48 min-[1568px]:block"
        aria-hidden
      >
        <div className="hero-signal-card-surface relative h-full w-full rounded-3xl border border-white/10 backdrop-blur-md">
          <div className="hero-signal-card-grid pointer-events-none absolute inset-0 rounded-3xl" aria-hidden />
        </div>
      </motion.div>

      <div className="relative z-10 mx-auto grid w-full max-w-6xl flex-1 grid-cols-1 content-center gap-8 px-4 sm:px-6 xl:grid-cols-[minmax(0,1fr)_17.5rem] xl:items-center xl:gap-10">
        <div className="min-w-0">
          <Reveal>
            <div className="hero-badge-pulse inline-flex items-center gap-2.5 rounded-full border border-signal/35 bg-signal/[0.11] px-4 py-1.5 font-mono text-xs text-signal shadow-glow-sm backdrop-blur-sm">
              <span className="relative flex h-2 w-2 shrink-0" aria-hidden>
                <span className="absolute inline-flex h-full w-full rounded-full bg-signal/35 blur-[3px]" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-signal shadow-[0_0_14px_rgba(8,185,139,0.9)]" />
              </span>
              <span>Python CLI - local clone evaluation - GitHub / Azure / AWS profiles</span>
            </div>
          </Reveal>

          <div className="relative mt-8">
            <Reveal delay={0.05} y={0}>
              <h1 className="hero-headline max-w-4xl text-4xl font-semibold leading-[1.08] tracking-tight text-mist md:text-6xl lg:text-7xl">
                <span className="hero-headline-solid">Evaluate OSS repository governance and </span>
                <span className="text-gradient-signal">CI/CD security</span>
                <span className="hero-headline-solid"> from the clone you already have.</span>
              </h1>
            </Reveal>
          </div>

          <Reveal delay={0.12} className="mt-6 max-w-2xl text-lg leading-relaxed text-slate md:text-xl">
            {siteConfig.name} is a Python starter kit with{" "}
            <strong className="font-medium text-mist">versioned controls</strong>,{" "}
            <strong className="font-medium text-mist">staged profiles</strong>, optional evidence
            inputs, and <strong className="font-medium text-mist">Markdown + JSON</strong> reports
            for repositories and pipelines. GitHub is the most mature path today; Azure and AWS are
            supported as clone-based, evidence-driven tracks.
          </Reveal>

          <Reveal delay={0.18} className="mt-10 flex flex-wrap gap-3">
            <a
              href={siteConfig.githubRepo}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-2 rounded-xl bg-signal px-5 py-3 text-sm font-semibold text-ink shadow-glow transition hover:bg-signal/90 hover:shadow-[0_0_40px_-6px_rgba(8,185,139,0.55)]"
            >
              View repository
              <ArrowRight className="h-4 w-4" aria-hidden />
            </a>
            <button
              type="button"
              onClick={() => scrollTo("quickstart")}
              className="inline-flex items-center gap-2 rounded-xl border border-white/15 bg-white/5 px-5 py-3 text-sm font-medium text-mist shadow-sm backdrop-blur transition hover:border-signal/45 hover:bg-white/[0.09] hover:shadow-[0_0_28px_-10px_rgba(8,185,139,0.25)]"
            >
              See quickstart
            </button>
            <button
              type="button"
              onClick={() => scrollTo("profiles")}
              className="inline-flex items-center gap-2 rounded-xl border border-white/10 px-5 py-3 text-sm font-medium text-slate transition hover:border-white/18 hover:text-mist hover:shadow-sm"
            >
              Browse profiles
            </button>
          </Reveal>

          <Reveal delay={0.22} className="mt-14">
            <p className="mb-4 font-mono text-xs uppercase tracking-widest text-steel">
              Core vocabulary
            </p>
            <div className="flex flex-wrap gap-2">
              {keywords.map((k, i) => (
                <motion.span
                  key={k}
                  initial={reduce ? false : { opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.04 * i, duration: 0.45 }}
                  className="rounded-lg border border-white/10 bg-white/[0.045] px-3 py-1.5 font-mono text-xs text-mist/95 shadow-sm backdrop-blur transition duration-300 hover:border-signal/25 hover:bg-white/[0.07] hover:shadow-[0_0_20px_-8px_rgba(8,185,139,0.2)]"
                >
                  {k}
                </motion.span>
              ))}
            </div>
          </Reveal>
        </div>

        <motion.aside
          style={{ opacity: op, y: y2 }}
          className="pointer-events-none relative hidden min-h-[15.5rem] w-full max-w-md justify-self-end xl:block xl:max-w-none"
          aria-hidden
        >
          <JsonPanelDecor />
        </motion.aside>

        <div className="pointer-events-none relative w-full max-w-md justify-self-start xl:hidden" aria-hidden>
          <JsonPanelDecor />
        </div>
      </div>

      <button
        type="button"
        aria-label="Scroll to problem statement"
        onClick={() => scrollTo("problem")}
        className="group absolute bottom-8 left-1/2 z-20 flex -translate-x-1/2 flex-col items-center gap-1 rounded-2xl px-3 py-1 text-slate transition hover:text-signal focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-signal/60"
      >
        <span className="text-xs font-mono uppercase tracking-widest opacity-80 group-hover:opacity-100">
          Scroll
        </span>
        <motion.span
          className="rounded-full p-0.5 ring-1 ring-transparent transition group-hover:ring-signal/35 group-hover:shadow-[0_0_24px_-6px_rgba(8,185,139,0.35)]"
          animate={reduce ? undefined : { y: [0, 6, 0] }}
          transition={{ duration: 1.6, repeat: Infinity, ease: "easeInOut" }}
        >
          <ChevronDown className="h-6 w-6" strokeWidth={2} aria-hidden />
        </motion.span>
      </button>
    </section>
  );
}
