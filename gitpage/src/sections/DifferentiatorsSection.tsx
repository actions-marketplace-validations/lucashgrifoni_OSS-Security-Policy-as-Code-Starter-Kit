import { Cpu, Layers, Sparkles, Target, Zap } from "lucide-react";
import { SectionShell } from "../components/layout/SectionShell";
import { Reveal } from "../components/effects/Reveal";

const items = [
  {
    icon: Layers,
    title: "Honest trust model",
    body: "The kit distinguishes clone-visible truth, self-attested evidence, and platform-only reality instead of collapsing them into one confidence claim.",
  },
  {
    icon: Cpu,
    title: "Useful command surface",
    body: "The CLI does more than one demo command: it supports profile discovery, recommendation, batch evaluation, evidence scaffolding, summaries, and CI thresholds.",
  },
  {
    icon: Zap,
    title: "Small and inspectable",
    body: "Controls, profiles, schemas, and parsers live in the repository in plain files, which makes the project easier to audit and easier to fork responsibly.",
  },
  {
    icon: Target,
    title: "Built for adoption",
    body: "Fixtures, docs, templates, screenshots, and the GitHub Pages site make the kit easier to demo, teach, and operationalize with maintainers.",
  },
  {
    icon: Sparkles,
    title: "One output for people and automation",
    body: "The same evaluation produces narrative Markdown for review and structured JSON for pipelines, integrations, and regression checks.",
  },
] as const;

export function DifferentiatorsSection() {
  return (
    <SectionShell
      id="differentiators"
      eyebrow="Differentiators"
      title="What makes this project useful is not polish alone, but operational honesty."
      subtitle="It is designed for real maintainers and AppSec engineers who need evidence they can explain, not just output that looks impressive in a screenshot."
    >
      <div className="space-y-5">
        {items.map((it, i) => (
          <Reveal key={it.title} delay={0.06 * i}>
            <div className="group flex flex-col gap-4 rounded-3xl border border-white/10 bg-gradient-to-r from-white/[0.04] to-transparent p-6 transition hover:border-signal/30 hover:shadow-glow-sm md:flex-row md:items-center md:gap-8 md:p-8">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-signal/30 bg-signal/10 text-signal shadow-glow-sm transition group-hover:scale-[1.03]">
                <it.icon className="h-7 w-7" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-mist">{it.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate md:text-base">{it.body}</p>
              </div>
            </div>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}
