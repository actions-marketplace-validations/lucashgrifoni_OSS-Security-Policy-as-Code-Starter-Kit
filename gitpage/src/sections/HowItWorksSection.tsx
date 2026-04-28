import { motion, useReducedMotion } from "framer-motion";
import { FileJson, GitMerge, Radar, ScrollText, ShieldCheck, Sliders } from "lucide-react";
import { SectionShell } from "../components/layout/SectionShell";

const steps = [
  {
    icon: Sliders,
    title: "Discover the right profile",
    body: "Start with `profiles` or `recommend-profile` to choose the platform and strictness level that matches the repository you actually have.",
  },
  {
    icon: GitMerge,
    title: "Point the CLI at a clone",
    body: "Run `python -m oss_policy_kit evaluate --target <repo> --profile <profile>` against the working tree you want to inspect.",
  },
  {
    icon: Radar,
    title: "Layer in optional evidence",
    body: "Add waivers, Scorecard JSON, or `.oss-policy-kit/evidence/` files only when you need extra context for release-hardening or program review.",
  },
  {
    icon: ShieldCheck,
    title: "Resolve explicit control states",
    body: "Each control ends as pass, fail, manual-review-required, self-attested, not-observable, not-applicable, or waived.",
  },
  {
    icon: ScrollText,
    title: "Write reports for humans and CI",
    body: "The evaluator writes `evaluation-report.md` and `evaluation-report.json`, and it can emit compact machine summaries with `--summary-only --format json`.",
  },
  {
    icon: FileJson,
    title: "Reuse it in pipelines or batches",
    body: "Use `--fail-on` for CI gates and `evaluate-many` when you want one pass over multiple child repositories or apps.",
  },
] as const;

export function HowItWorksSection() {
  const reduce = useReducedMotion();

  return (
    <SectionShell
      id="flow"
      eyebrow="Execution model"
      title="The workflow is practical: choose a profile, evaluate the clone, keep the evidence."
      subtitle="Nothing here depends on a remote service. The same flow works for local self-checks, demos, and CI gates."
    >
      <div className="relative">
        <div
          className="absolute left-[22px] top-0 hidden h-full w-px bg-gradient-to-b from-signal/50 via-signal/20 to-transparent md:block"
          aria-hidden
        />
        <ol className="space-y-10 md:space-y-12">
          {steps.map((s, i) => (
            <motion.li
              key={s.title}
              initial={reduce ? false : { opacity: 0, x: -16 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, margin: "-12%" }}
              transition={{ delay: 0.06 * i, duration: 0.5 }}
              className="relative flex flex-col gap-4 md:flex-row md:gap-10"
            >
              <div className="flex items-start gap-4 md:w-52 md:shrink-0 md:flex-col md:items-center">
                <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-signal/35 bg-signal/10 text-signal shadow-glow-sm">
                  <s.icon className="h-5 w-5" aria-hidden />
                </span>
                <span className="font-mono text-xs text-steel md:text-center">Step {i + 1}</span>
              </div>
              <div className="glass-panel flex-1 rounded-2xl p-6 md:p-8">
                <h3 className="text-lg font-semibold text-mist">{s.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate md:text-base">{s.body}</p>
              </div>
            </motion.li>
          ))}
        </ol>
      </div>
    </SectionShell>
  );
}
