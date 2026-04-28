import { BadgeCheck, BookMarked, Github, Radar } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { SectionShell } from "../components/layout/SectionShell";
import { cn } from "../lib/cn";

const frameworks = [
  {
    icon: BookMarked,
    name: "GitHub baseline ladder",
    text: "`github-level-1..3` is the most mature path in the kit. It inspects governance files and GitHub Actions posture with increasing strictness.",
    chips: ["16-22 controls", "clone-visible", "most mature"],
  },
  {
    icon: Radar,
    name: "GitHub release hardening",
    text: "`github-release-hardening-1..3` extends the baseline with branch protection, rulesets, environments, and secret scanning evidence flows.",
    chips: ["17-26 controls", "evidence files", "manual review if missing"],
  },
  {
    icon: BadgeCheck,
    name: "Azure tracks",
    text: "`azure-level-1..3` and `azure-release-hardening-1..3` cover clone-visible Azure Repos and Azure Pipelines signals plus optional evidence.",
    chips: ["12-17 controls", "clone + evidence", "static parsing"],
  },
  {
    icon: Github,
    name: "AWS tracks",
    text: "`aws-level-1..3` and `aws-release-hardening-1..3` cover CodeBuild, committed CodePipeline artifacts, and optional exported evidence files.",
    chips: ["11-17 controls", "clone + evidence", "static parsing"],
  },
] as const;

export function FrameworksSection() {
  const reduce = useReducedMotion();

  return (
    <SectionShell
      id="profiles"
      eyebrow="Bundled profiles"
      title="Profile families let teams start small and harden posture without changing tools."
      subtitle="GitHub support is the strongest path today. Azure and AWS are intentionally clone-based and evidence-driven rather than remote platform verification."
      className="bg-gradient-to-b from-transparent via-signal/[0.03] to-transparent"
    >
      <div className="grid gap-5 md:grid-cols-2">
        {frameworks.map((f, i) => (
          <motion.article
            key={f.name}
            initial={reduce ? false : { opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.07 * i, duration: 0.55 }}
            className="glass-panel relative overflow-hidden rounded-3xl p-8"
          >
            <div className="pointer-events-none absolute -right-16 -top-16 h-40 w-40 rounded-full bg-signal/10 blur-3xl" />
            <f.icon className="relative z-[1] mb-4 h-9 w-9 text-signal" />
            <h3 className="relative z-[1] text-xl font-semibold text-mist">{f.name}</h3>
            <p className="relative z-[1] mt-3 text-sm leading-relaxed text-slate">{f.text}</p>
            <div className="relative z-[1] mt-5 flex flex-wrap gap-2">
              {f.chips.map((c) => (
                <span
                  key={c}
                  className={cn(
                    "rounded-md border border-white/10 bg-white/[0.04] px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider text-slate",
                  )}
                >
                  {c}
                </span>
              ))}
            </div>
          </motion.article>
        ))}
      </div>
    </SectionShell>
  );
}
