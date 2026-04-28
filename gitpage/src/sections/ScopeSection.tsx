import { type LucideIcon, Check, X } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";
import { SectionShell } from "../components/layout/SectionShell";
import { Reveal } from "../components/effects/Reveal";
import { cn } from "../lib/cn";

const isList = [
  "Python CLI that evaluates a local repository clone and writes Markdown + JSON reports",
  "Bundled profile families for GitHub, Azure, and AWS with staged level and release-hardening tracks",
  "Governance, workflow, and pipeline checks that stay inside clone-visible boundaries unless optional evidence is supplied",
  "Commands for profile discovery, profile recommendation, batch evaluation, and evidence scaffolding",
  "Optional waivers YAML and optional OpenSSF Scorecard JSON as additive local context",
  "Built-in hardened and vulnerable fixtures, templates, and docs for demos and onboarding",
  "Explicit remediation, confidence, and non-pass states instead of a single maturity score",
] as const;

const notList = [
  "Live verifier for GitHub settings, Azure policies, or AWS configuration outside the clone",
  "Universal SAST, DAST, dependency scanner, or application security platform",
  "Compliance certification engine, OSPS attestation service, or guarantee of secure posture",
  "Dashboard-first SaaS control plane that invents passes when evidence is missing",
] as const;

function Column({
  title,
  tone,
  items,
  icon: Icon,
}: {
  title: string;
  tone: "yes" | "no";
  items: readonly string[];
  icon: LucideIcon;
}) {
  const reduce = useReducedMotion();
  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-10%" }}
      transition={{ duration: 0.55 }}
      className={cn(
        "glass-panel relative overflow-hidden rounded-3xl p-8 md:p-10",
        tone === "yes" ? "border-signal/25" : "border-white/10",
      )}
    >
      <div
        className={cn(
          "mb-6 inline-flex items-center gap-2 rounded-full px-3 py-1 font-mono text-xs uppercase tracking-widest",
          tone === "yes" ? "bg-signal/15 text-signal" : "bg-white/5 text-slate",
        )}
      >
        <Icon className="h-3.5 w-3.5" />
        {title}
      </div>
      <ul className="space-y-4">
        {items.map((item) => (
          <li key={item} className="flex gap-3 text-sm leading-relaxed text-mist/95">
            <span
              className={cn(
                "mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md border text-xs",
                tone === "yes"
                  ? "border-signal/40 bg-signal/10 text-signal"
                  : "border-white/15 bg-white/5 text-slate",
              )}
            >
              {tone === "yes" ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
            </span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </motion.div>
  );
}

export function ScopeSection() {
  return (
    <SectionShell
      id="scope"
      eyebrow="Positioning"
      title="The scope is intentionally narrow because honest outputs are more useful than broad promises."
      subtitle="The kit is small, test-backed, and explicit about which results are automated, self-attested, or still blocked on manual review."
      className="bg-gradient-to-b from-transparent via-white/[0.02] to-transparent"
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <Reveal>
          <Column title="What it is" tone="yes" items={isList} icon={Check} />
        </Reveal>
        <Reveal delay={0.08}>
          <Column title="What it is not" tone="no" items={notList} icon={X} />
        </Reveal>
      </div>
    </SectionShell>
  );
}
