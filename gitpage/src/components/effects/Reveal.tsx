import { type ReactNode } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { useInView } from "react-intersection-observer";
import { cn } from "../../lib/cn";

const ease = [0.22, 1, 0.36, 1] as const;

export function Reveal({
  children,
  className,
  delay = 0,
  y = 28,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
  y?: number;
}) {
  const reduce = useReducedMotion();
  const { ref, inView } = useInView({ triggerOnce: true, rootMargin: "-12% 0px" });

  return (
    <motion.div
      ref={ref}
      className={cn(className)}
      initial={reduce ? false : { opacity: 0, y }}
      animate={inView ? { opacity: 1, y: 0 } : reduce ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.65, ease, delay }}
    >
      {children}
    </motion.div>
  );
}
