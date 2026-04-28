import { motion, useReducedMotion } from "framer-motion";
import { ParticleCanvas } from "../effects/ParticleCanvas";

export function AmbientBackground() {
  const reduce = useReducedMotion();

  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute inset-0 bg-mesh-premium" />
      <div className="absolute inset-0 bg-radial-signal opacity-[0.82]" />
      <div className="absolute inset-0 bg-radial-ink opacity-95" />
      <ParticleCanvas className="absolute inset-0 h-full w-full opacity-[0.38]" />
      <div className="absolute inset-0 grid-lines opacity-[0.16]" />
      {!reduce ? (
        <>
          <motion.div
            className="absolute -left-[20%] top-[10%] h-[420px] w-[420px] rounded-full bg-signal/[0.06] blur-[120px]"
            animate={{ x: [0, 40, 0], y: [0, -30, 0], scale: [1, 1.08, 1] }}
            transition={{ duration: 22, repeat: Infinity, ease: "easeInOut" }}
          />
          <motion.div
            className="absolute -right-[15%] bottom-[5%] h-[380px] w-[380px] rounded-full bg-slate/[0.14] blur-[100px]"
            animate={{ x: [0, -30, 0], y: [0, 24, 0] }}
            transition={{ duration: 18, repeat: Infinity, ease: "easeInOut" }}
          />
        </>
      ) : null}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-ink/32 to-ink" />
    </div>
  );
}
