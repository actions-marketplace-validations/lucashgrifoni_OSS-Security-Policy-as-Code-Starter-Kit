import { motion, useReducedMotion } from "framer-motion";
import { Network, Rocket, Satellite, Shield } from "lucide-react";
import { SectionShell } from "../components/layout/SectionShell";

const milestones = [
  {
    id: "current",
    title: "Shipped today",
    icon: Rocket,
    era: "Current state",
    bullets: [
      "Packaged Python CLI with `evaluate`, `profiles`, `recommend-profile`, `evaluate-many`, and `scaffold-evidence`",
      "Eighteen bundled profiles across GitHub, Azure, and AWS",
      "Markdown + JSON reports, optional waivers, optional Scorecard JSON, and schema-shaped evidence inputs",
      "Examples, tests, documentation, screenshots, and the public GitHub Pages site in the same repository",
    ],
  },
  {
    id: "next",
    title: "Hardening next",
    icon: Shield,
    era: "Near term",
    bullets: [
      "Richer documentation and better evidence-pack guidance for release-hardening flows",
      "Additional controls only where static analysis can remain reliable and explainable",
      "More parser edge-case coverage and regression tests around workflow and pipeline semantics",
      "Sharper examples for self-check, CI-gating, and package-consumer installation paths",
    ],
  },
  {
    id: "later",
    title: "Selective depth",
    icon: Satellite,
    era: "Later",
    bullets: [
      "Security-insights validation only if ecosystem semantics become stable enough to support it honestly",
      "Narrow remote adapters for a small set of platform signals where trust boundaries can stay explicit",
      "Better aggregated views on top of `evaluate-many` without turning the project into a dashboard product",
      "Incremental improvements to cross-platform parity without pretending every forge exposes the same truth model",
    ],
  },
  {
    id: "guardrails",
    title: "Guardrails",
    icon: Network,
    era: "Stays true",
    bullets: [
      "No fake remote verification from clone-only data",
      "No universal scanner claims or certification theater",
      "No shift toward SaaS control planes at the expense of evidence quality and inspectability",
    ],
  },
] as const;

export function RoadmapSection() {
  const reduce = useReducedMotion();

  return (
    <SectionShell
      id="roadmap"
      eyebrow="Roadmap"
      title="The roadmap is conservative: deepen evidence quality without losing scope discipline."
      subtitle="What matters here is not surface area. It is keeping the kit useful, explainable, and safe to trust for the things it claims to evaluate."
      className="bg-gradient-to-b from-transparent via-white/[0.02] to-transparent"
    >
      <div className="relative">
        <div
          className="absolute bottom-6 left-14 top-6 hidden w-px bg-gradient-to-b from-signal via-signal/30 to-transparent md:block"
          aria-hidden
        />
        <div className="space-y-12 md:space-y-16">
          {milestones.map((m, i) => (
            <motion.div
              key={m.id}
              initial={reduce ? false : { opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-10%" }}
              transition={{ delay: 0.08 * i, duration: 0.55 }}
              className="relative md:pl-36"
            >
              <div className="mb-4 flex items-center gap-4 md:absolute md:left-0 md:top-1/2 md:mb-0 md:w-28 md:-translate-y-1/2 md:flex-col md:items-center md:gap-3">
                <span className="flex h-10 w-10 items-center justify-center rounded-2xl border border-signal/40 bg-signal/10 text-signal shadow-glow-sm">
                  <m.icon className="h-5 w-5" />
                </span>
                <span className="text-center font-mono text-[11px] uppercase tracking-[0.26em] text-steel">
                  {m.era}
                </span>
              </div>
              <div className="glass-panel rounded-3xl p-8">
                <div className="flex flex-wrap items-end gap-3">
                  <h3 className="text-2xl font-semibold text-mist">{m.title}</h3>
                  <span className="rounded-md border border-white/10 px-2 py-0.5 font-mono text-[10px] text-slate">
                    directional
                  </span>
                </div>
                <ul className="mt-6 space-y-3">
                  {m.bullets.map((b) => (
                    <li
                      key={b}
                      className="flex gap-3 text-sm leading-relaxed text-slate md:text-base"
                    >
                      <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-signal" />
                      <span>{b}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </SectionShell>
  );
}
