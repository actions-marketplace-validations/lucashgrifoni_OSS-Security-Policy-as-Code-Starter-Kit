import { type ReactNode } from "react";
import { cn } from "../../lib/cn";
import { Reveal } from "../effects/Reveal";

export function SectionShell({
  id,
  eyebrow,
  title,
  subtitle,
  children,
  className,
  contentClassName,
}: {
  id: string;
  eyebrow: string;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
}) {
  return (
    <section
      id={id}
      className={cn("relative scroll-mt-24 py-20 md:scroll-mt-28 md:py-28", className)}
    >
      <div className={cn("mx-auto max-w-6xl px-4 sm:px-6", contentClassName)}>
        <Reveal>
          <p className="mb-3 font-mono text-xs uppercase tracking-[0.28em] text-signal/90">
            {eyebrow}
          </p>
          <h2 className="max-w-3xl text-3xl font-semibold tracking-tight text-mist md:text-4xl">
            {title}
          </h2>
          {subtitle ? (
            <p className="mt-4 max-w-2xl text-base leading-relaxed text-slate md:text-lg">
              {subtitle}
            </p>
          ) : null}
        </Reveal>
        <div className="mt-12">{children}</div>
      </div>
    </section>
  );
}
