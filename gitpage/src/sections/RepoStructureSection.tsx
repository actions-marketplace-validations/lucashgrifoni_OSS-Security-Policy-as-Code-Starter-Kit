import { motion, useReducedMotion } from "framer-motion";
import { SectionShell } from "../components/layout/SectionShell";
import { Reveal } from "../components/effects/Reveal";
import { cn } from "../lib/cn";

const blocks = [
  { id: "package", label: "src/oss_policy_kit", hint: "CLI, engine, evaluators, parsers" },
  { id: "data", label: "src/.../data", hint: "Controls, profiles, schemas" },
  { id: "docs", label: "docs", hint: "Adoption, architecture, release notes" },
  { id: "examples", label: "examples", hint: "Hardened and vulnerable fixtures" },
  { id: "tests", label: "tests", hint: "Regression coverage for package behavior" },
  { id: "templates", label: "templates", hint: "Governance starter files and examples" },
  { id: "waivers", label: "waivers", hint: "Waiver examples and exception flows" },
  { id: "gitpage", label: "gitpage", hint: "Public project site for GitHub Pages" },
] as const;

export function RepoStructureSection() {
  const reduce = useReducedMotion();

  return (
    <SectionShell
      id="architecture"
      eyebrow="Repository anatomy"
      title="The repository already packages code, policy data, fixtures, docs, and the public site."
      subtitle="That makes the project easier to validate end to end: the kit can test itself, document itself, and demonstrate itself from one source tree."
    >
      <Reveal>
        <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-ink/80 p-6 md:p-10">
          <div className="pointer-events-none absolute inset-0 opacity-40">
            <div
              className="absolute inset-0"
              style={{
                backgroundImage:
                  "linear-gradient(rgba(8,185,139,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(8,185,139,0.08) 1px, transparent 1px)",
                backgroundSize: "32px 32px",
              }}
            />
          </div>

          <div className="relative grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {blocks.map((b, i) => (
              <motion.div
                key={b.id}
                initial={reduce ? false : { opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: 0.05 * i, duration: 0.45 }}
                className={cn(
                  "rounded-2xl border border-white/10 bg-white/[0.04] p-5 backdrop-blur",
                  "hover:border-signal/35 hover:shadow-glow-sm",
                )}
              >
                <p className="font-mono text-sm font-semibold text-signal">{b.label}/</p>
                <p className="mt-2 text-xs leading-relaxed text-slate">{b.hint}</p>
              </motion.div>
            ))}
          </div>

          <p className="relative mt-8 max-w-3xl text-sm text-slate">
            The repository is intentionally self-contained. Package logic, policy payloads,
            evidence schemas, fixtures, and documentation all live together so maintainers can see
            exactly what the kit ships today.
          </p>
        </div>
      </Reveal>
    </SectionShell>
  );
}
