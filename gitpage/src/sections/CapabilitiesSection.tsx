import {
  BookOpen,
  ClipboardList,
  FileKey,
  FileWarning,
  Fingerprint,
  Gauge,
  GitPullRequest,
  Link2,
  Lock,
  Package,
  Scan,
  Shield,
} from "lucide-react";
import { SectionShell } from "../components/layout/SectionShell";
import { Reveal } from "../components/effects/Reveal";
import { TiltCard } from "../components/effects/TiltCard";

const capabilities = [
  {
    icon: ClipboardList,
    title: "Bundled control catalog",
    body: "Versioned YAML control data and staged profiles define what the kit checks without hiding policy behind hard-coded heuristics.",
  },
  {
    icon: BookOpen,
    title: "Documented CLI surface",
    body: "The public contract includes `evaluate`, `profiles`, `recommend-profile`, `evaluate-many`, and `scaffold-evidence`.",
  },
  {
    icon: Scan,
    title: "GitHub Actions hygiene",
    body: "Static workflow analysis covers governance signals, token permissions, action pinning, risky triggers, and other high-value repository checks.",
  },
  {
    icon: Lock,
    title: "Explicit trust boundaries",
    body: "When branch protection, rulesets, or other platform controls cannot be proven from a clone, the kit degrades honestly instead of fabricating a pass.",
  },
  {
    icon: FileKey,
    title: "Structured evidence inputs",
    body: "Release-hardening profiles can consume schema-shaped evidence files under `.oss-policy-kit/evidence/` when local files alone are not enough.",
  },
  {
    icon: Package,
    title: "Release-hardening tracks",
    body: "GitHub, Azure, and AWS all ship release-oriented profile families that extend baseline checks with evidence-driven posture expectations.",
  },
  {
    icon: Link2,
    title: "OpenSSF Scorecard bridge",
    body: "Optional Scorecard JSON can be ingested as supplemental context without becoming a second source of truth.",
  },
  {
    icon: Shield,
    title: "Cross-platform parsers",
    body: "The package includes static parsers for GitHub Actions, Azure Pipelines, and AWS CodeBuild or committed CodePipeline definitions.",
  },
  {
    icon: FileWarning,
    title: "Markdown + JSON reports",
    body: "Every run writes artifacts that work for both human review and machine consumption, with structured summaries available on stdout when needed.",
  },
  {
    icon: GitPullRequest,
    title: "Traceable waivers",
    body: "Exceptions can be loaded from waivers YAML so non-pass decisions stay visible, reviewable, and time-bounded.",
  },
  {
    icon: Gauge,
    title: "Batch evaluation",
    body: "Immediate child directories can be evaluated in one pass with consolidated batch reports for multi-repo or multi-app roots.",
  },
  {
    icon: Fingerprint,
    title: "Examples, tests, and docs",
    body: "The repository ships fixtures, screenshots, documentation, and a regression suite so the kit can validate itself publicly.",
  },
] as const;

export function CapabilitiesSection() {
  return (
    <SectionShell
      id="capabilities"
      eyebrow="Capability matrix"
      title="The project ships the actual pieces you need to evaluate, explain, and gate repository posture."
      subtitle="These are implementation capabilities in the repository today, not aspirational product bullets."
    >
      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-3">
        {capabilities.map((c, i) => (
          <Reveal key={c.title} delay={0.03 * (i % 6)}>
            <TiltCard className="h-full">
              <c.icon className="mb-4 h-7 w-7 text-signal" />
              <h3 className="text-base font-semibold text-mist">{c.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate">{c.body}</p>
            </TiltCard>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}
