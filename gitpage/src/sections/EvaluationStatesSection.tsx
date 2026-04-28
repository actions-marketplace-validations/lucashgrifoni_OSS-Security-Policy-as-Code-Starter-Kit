import { SectionShell } from "../components/layout/SectionShell";
import { Reveal } from "../components/effects/Reveal";
import { motion, useReducedMotion } from "framer-motion";
import { cn } from "../lib/cn";

const states = [
  {
    id: "pass",
    label: "pass",
    desc: "The evaluator observed a positive signal for the control in the clone or in accepted supporting evidence.",
    tone: "signal",
  },
  {
    id: "fail",
    label: "fail",
    desc: "A required signal was missing or a high-value problem was found in files, workflows, or supplied evidence.",
    tone: "rose",
  },
  {
    id: "manual-review-required",
    label: "manual-review-required",
    desc: "The control cannot be safely proven from a local clone alone, so platform confirmation or human review is still required.",
    tone: "amber",
  },
  {
    id: "self-attested",
    label: "self-attested",
    desc: "Maintainer-supplied local evidence exists, but trust still depends on honesty and review discipline rather than remote verification.",
    tone: "slate",
  },
  {
    id: "not-observable",
    label: "not-observable",
    desc: "The control exists conceptually, but the evaluated artifact set does not contain enough material to observe it safely.",
    tone: "muted",
  },
  {
    id: "not-applicable",
    label: "not-applicable",
    desc: "The control does not apply to the evaluated repository shape, such as a repo that intentionally has no workflows.",
    tone: "muted",
  },
  {
    id: "waived",
    label: "waived",
    desc: "A documented exception overrode a non-pass outcome and remains visible in the report as an explicit decision.",
    tone: "violet",
  },
] as const;

const toneClass: Record<(typeof states)[number]["tone"], string> = {
  signal: "border-signal/50 bg-signal/10 text-signal",
  rose: "border-red-400/40 bg-red-500/10 text-red-200",
  amber: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  slate: "border-slate/50 bg-white/5 text-slate",
  muted: "border-white/10 bg-white/[0.03] text-slate",
  violet: "border-violet-400/35 bg-violet-500/10 text-violet-100",
};

const fields = [
  "control id",
  "status",
  "evidence sources",
  "confidence",
  "reason",
  "remediation",
  "waiver metadata",
] as const;

export function EvaluationStatesSection() {
  const reduce = useReducedMotion();

  return (
    <SectionShell
      id="states"
      eyebrow="Evaluation model"
      title="Every control resolves to an explicit state, not to a hidden score."
      subtitle="That makes the output usable in triage, audit, and CI because teams can see what was proven, what was waived, and what still needs manual follow-up."
    >
      <div className="grid gap-4 lg:grid-cols-2">
        {states.map((s, i) => (
          <Reveal key={s.id} delay={0.04 * i}>
            <motion.div
              whileHover={reduce ? undefined : { y: -3 }}
              className={cn(
                "rounded-2xl border p-5 transition-shadow hover:shadow-glow-sm",
                toneClass[s.tone],
              )}
            >
              <code className="font-mono text-sm font-semibold tracking-tight">{s.label}</code>
              <p className="mt-2 text-sm leading-relaxed text-mist/90">{s.desc}</p>
            </motion.div>
          </Reveal>
        ))}
      </div>

      <Reveal className="mt-12">
        <div className="glass-panel rounded-3xl p-8 md:p-10">
          <h3 className="text-lg font-semibold text-mist">Structured control records</h3>
          <p className="mt-2 max-w-3xl text-sm text-slate">
            Each evaluated control carries fields meant to survive handoff from terminal output to a
            backlog item or review note:
          </p>
          <ul className="mt-6 flex flex-wrap gap-2">
            {fields.map((f) => (
              <li
                key={f}
                className="rounded-lg border border-white/10 bg-ink/60 px-3 py-2 font-mono text-xs text-mist"
              >
                {f}
              </li>
            ))}
          </ul>
        </div>
      </Reveal>
    </SectionShell>
  );
}
