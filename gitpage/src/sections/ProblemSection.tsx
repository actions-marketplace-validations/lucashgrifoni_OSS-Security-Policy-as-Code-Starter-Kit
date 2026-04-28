import { AlertTriangle, GitBranch, Scale, Workflow } from "lucide-react";
import { SectionShell } from "../components/layout/SectionShell";
import { Reveal } from "../components/effects/Reveal";
import { TiltCard } from "../components/effects/TiltCard";

const pains = [
  {
    icon: Scale,
    title: "Clone truth is limited",
    body: "Repository files can prove some things well, suggest other things weakly, and say nothing about live platform settings. Most tools blur those lines.",
  },
  {
    icon: Workflow,
    title: "Baselines become hand-wavy",
    body: "Teams talk about OSS security maturity, but translating that into versioned controls, profiles, and repeatable checks is usually where momentum dies.",
  },
  {
    icon: GitBranch,
    title: "Governance and pipelines drift apart",
    body: "SECURITY.md, CODEOWNERS, workflow permissions, release posture, and waiver decisions often live in different conversations instead of one evidence trail.",
  },
  {
    icon: AlertTriangle,
    title: "Dashboards hide the hard part",
    body: "A green score does not tell you what was observed, what was assumed, and what still needs manual review. Program reviews need that distinction.",
  },
] as const;

export function ProblemSection() {
  return (
    <SectionShell
      id="problem"
      eyebrow="Problem space"
      title="OSS security posture is easy to describe and surprisingly hard to verify honestly."
      subtitle="This kit turns that gap into a concrete workflow: pick a profile, inspect a local clone, add optional evidence, and keep every unresolved boundary visible."
    >
      <div className="grid gap-5 md:grid-cols-2">
        {pains.map((p, i) => (
          <Reveal key={p.title} delay={0.06 * i}>
            <TiltCard>
              <p.icon className="mb-4 h-8 w-8 text-signal" aria-hidden />
              <h3 className="text-lg font-semibold text-mist">{p.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate">{p.body}</p>
            </TiltCard>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}
