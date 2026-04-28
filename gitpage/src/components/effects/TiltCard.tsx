import { type ReactNode, useRef } from "react";
import {
  motion,
  useMotionTemplate,
  useMotionValue,
  useReducedMotion,
  useSpring,
} from "framer-motion";
import { cn } from "../../lib/cn";

export function TiltCard({
  children,
  className,
  glow = true,
}: {
  children: ReactNode;
  className?: string;
  glow?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const reduce = useReducedMotion();
  const mx = useMotionValue(50);
  const my = useMotionValue(50);
  const rotateXRaw = useMotionValue(0);
  const rotateYRaw = useMotionValue(0);
  const rotateX = useSpring(rotateXRaw, { stiffness: 260, damping: 22 });
  const rotateY = useSpring(rotateYRaw, { stiffness: 260, damping: 22 });

  const spotlight = useMotionTemplate`radial-gradient(420px circle at ${mx}% ${my}%, rgba(8,185,139,0.22), transparent 55%)`;

  const onMove = (e: React.MouseEvent) => {
    if (reduce || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width;
    const py = (e.clientY - r.top) / r.height;
    mx.set(px * 100);
    my.set(py * 100);
    rotateYRaw.set((px - 0.5) * -10);
    rotateXRaw.set((py - 0.5) * 10);
  };

  const onLeave = () => {
    rotateXRaw.set(0);
    rotateYRaw.set(0);
    mx.set(50);
    my.set(50);
  };

  return (
    <motion.div
      ref={ref}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      style={
        reduce
          ? undefined
          : {
              rotateX,
              rotateY,
              transformPerspective: 1100,
            }
      }
      className={cn(
        "relative rounded-2xl border border-white/10 bg-white/[0.03] p-6 shadow-panel transition-shadow duration-500 hover:border-signal/35 hover:shadow-glow-sm",
        className,
      )}
    >
      {glow && !reduce ? (
        <motion.div
          className="pointer-events-none absolute inset-0 rounded-2xl opacity-80"
          style={{ background: spotlight }}
        />
      ) : null}
      <div className="relative z-[1]">{children}</div>
    </motion.div>
  );
}
