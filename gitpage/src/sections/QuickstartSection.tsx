import { motion, useReducedMotion } from "framer-motion";
import { CheckCircle2, FolderKanban, ShieldCheck, TerminalSquare } from "lucide-react";
import { Reveal } from "../components/effects/Reveal";
import { SectionShell } from "../components/layout/SectionShell";

const steps = [
  {
    icon: TerminalSquare,
    title: "Install for local development",
    command: 'python -m pip install -e ".[dev]"',
    note: "Requires Python 3.12+. Release consumers can also install from GitHub Release wheel artifacts.",
  },
  {
    icon: FolderKanban,
    title: "List bundled profiles",
    command: "python -m oss_policy_kit profiles",
    note: "This build ships 18 profiles across GitHub, Azure, and AWS, including baseline and release-hardening tracks.",
  },
  {
    icon: ShieldCheck,
    title: "Run a self-check",
    command:
      "python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck",
    note: "The run writes evaluation-report.json and evaluation-report.md before you decide what to fix next.",
  },
  {
    icon: CheckCircle2,
    title: "Turn it into a CI gate",
    command:
      "python -m oss_policy_kit evaluate --target . --profile github-level-1 --output-dir ./out/selfcheck-ci --fail-on fail",
    note: "Reports are still written first; the CI step fails only after evidence is available for review.",
  },
] as const;

const extras = [
  "python -m oss_policy_kit recommend-profile --target .",
  "python -m oss_policy_kit evaluate-many --target-root ./apps --profiles github-level-1",
  "python -m oss_policy_kit scaffold-evidence --target . --platform github",
  "python -m oss_policy_kit evaluate --target . --profile github-level-1 --summary-only --format json",
] as const;

export function QuickstartSection() {
  const reduce = useReducedMotion();

  return (
    <SectionShell
      id="quickstart"
      eyebrow="Quickstart"
      title="Four commands are enough to understand how the kit works in practice."
      subtitle="The explicit evaluate subcommand is the preferred contract. The rest of the CLI expands from that same local-first model."
      className="bg-gradient-to-b from-transparent via-white/[0.02] to-transparent"
    >
      <div className="grid gap-5 lg:grid-cols-2">
        {steps.map((step, i) => (
          <Reveal key={step.title} delay={0.05 * i}>
            <motion.article
              whileHover={reduce ? undefined : { y: -4 }}
              className="glass-panel h-full rounded-3xl p-6 md:p-8"
            >
              <div className="flex items-center gap-3">
                <span className="flex h-11 w-11 items-center justify-center rounded-2xl border border-signal/35 bg-signal/10 text-signal shadow-glow-sm">
                  <step.icon className="h-5 w-5" aria-hidden />
                </span>
                <h3 className="text-lg font-semibold text-mist">{step.title}</h3>
              </div>
              <div className="mt-5 overflow-x-auto rounded-2xl border border-white/10 bg-ink/80 p-4">
                <code className="font-mono text-xs leading-relaxed text-mist">{step.command}</code>
              </div>
              <p className="mt-4 text-sm leading-relaxed text-slate">{step.note}</p>
            </motion.article>
          </Reveal>
        ))}
      </div>

      <Reveal className="mt-10">
        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-6 md:p-8">
          <p className="font-mono text-xs uppercase tracking-[0.24em] text-steel">
            Also useful
          </p>
          <div className="mt-5 grid gap-3 md:grid-cols-2">
            {extras.map((extra) => (
              <div
                key={extra}
                className="rounded-2xl border border-white/10 bg-ink/70 p-4 font-mono text-xs leading-relaxed text-mist"
              >
                {extra}
              </div>
            ))}
          </div>
        </div>
      </Reveal>
    </SectionShell>
  );
}
