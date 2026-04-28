import { AlertOctagon } from "lucide-react";
import { SectionShell } from "../components/layout/SectionShell";
import { Reveal } from "../components/effects/Reveal";
import { motion, useReducedMotion } from "framer-motion";

const examples = [
  "Missing `SECURITY.md`, `CONTRIBUTING.md`, or `LICENSE` in a repository that should expose basic governance signals.",
  "Missing `CODEOWNERS`, which leaves ownership and review expectations ambiguous for core paths.",
  "GitHub Actions jobs without explicit `permissions`, creating overly broad default token scope.",
  "Third-party GitHub Actions pinned to mutable tags instead of immutable commit SHAs.",
  "Dangerous `pull_request_target` patterns combined with checkout of untrusted code.",
  "Release-hardening profiles that expect branch protection, rulesets, or environment evidence but only have a local clone to inspect.",
  "Azure branch-policy or pipeline-governance expectations that cannot be proven without supplied evidence files.",
  "AWS CodeBuild or committed CodePipeline posture expected by the selected profile but missing from the evaluated artifact set.",
] as const;

export function ControlExamplesSection() {
  const reduce = useReducedMotion();

  return (
    <SectionShell
      id="examples"
      eyebrow="Signal library"
      title="Representative signals span governance files, workflow hygiene, and release-hardening evidence."
      subtitle="These are examples of the kinds of findings and non-pass states the bundled catalog can emit today."
    >
      <div className="columns-1 gap-4 space-y-4 md:columns-2">
        {examples.map((text, i) => (
          <Reveal key={i} delay={0.04 * (i % 5)}>
            <motion.div
              whileHover={reduce ? undefined : { scale: 1.01 }}
              className="break-inside-avoid rounded-2xl border border-white/10 bg-white/[0.03] p-5"
            >
              <div className="flex items-start gap-3">
                <AlertOctagon className="mt-0.5 h-5 w-5 shrink-0 text-signal" aria-hidden />
                <p className="text-sm leading-relaxed text-mist/95">{text}</p>
              </div>
            </motion.div>
          </Reveal>
        ))}
      </div>
    </SectionShell>
  );
}
