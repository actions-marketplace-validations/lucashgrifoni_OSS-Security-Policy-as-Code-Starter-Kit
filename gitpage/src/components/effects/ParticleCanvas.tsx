import { useEffect, useRef } from "react";
import { usePrefersReducedMotion } from "../../hooks/usePrefersReducedMotion";

type Particle = { x: number; y: number; z: number; vx: number; vy: number; r: number };

export function ParticleCanvas({ className }: { className?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const reduced = usePrefersReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || reduced) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let raf = 0;
    let particles: Particle[] = [];
    let w = 0;
    let h = 0;
    let visible = document.visibilityState === "visible";

    const mqMobile = globalThis.matchMedia("(max-width: 767px)");

    const isMobile = () => mqMobile.matches;

    const stopLoop = () => {
      cancelAnimationFrame(raf);
      raf = 0;
    };

    const onVis = () => {
      visible = document.visibilityState === "visible";
      if (visible) startLoop();
      else stopLoop();
    };
    document.addEventListener("visibilitychange", onVis);

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const light = isMobile();
      const areaFactor = light ? 34000 : 24000;
      const cap = light ? 44 : 78;
      const count = Math.min(cap, Math.floor((w * h) / areaFactor));
      particles = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        z: Math.random(),
        vx: (Math.random() - 0.5) * (light ? 0.22 : 0.28),
        vy: (Math.random() - 0.5) * (light ? 0.22 : 0.28),
        r: 0.55 + Math.random() * 1.35,
      }));
    };

    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    mqMobile.addEventListener("change", resize);

    const tick = () => {
      if (!visible) {
        raf = 0;
        return;
      }

      const mobile = isMobile();
      const maxLinkDist = mobile ? 64 : 88;
      const maxLinkDistSq = maxLinkDist * maxLinkDist;
      const drawLinks = !mobile;

      ctx.clearRect(0, 0, w, h);
      const n = particles.length;

      for (let i = 0; i < n; i++) {
        const p = particles[i] as Particle;
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
      }

      if (drawLinks) {
        for (let i = 0; i < n; i++) {
          for (let j = i + 1; j < n; j++) {
            const a = particles[i] as Particle;
            const b = particles[j] as Particle;
            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const d2 = dx * dx + dy * dy;
            if (d2 >= maxLinkDistSq) continue;
            const dist = Math.sqrt(d2);
            const t = 1 - dist / maxLinkDist;
            const lineA = t * 0.055 * (0.45 + a.z * 0.55) * (0.45 + b.z * 0.55);
            ctx.beginPath();
            ctx.strokeStyle = `rgba(8,185,139,${lineA})`;
            ctx.lineWidth = 0.55;
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      for (const p of particles) {
        const alpha = 0.1 + p.z * 0.42;
        const glow = 0.04 + p.z * 0.06;
        ctx.beginPath();
        ctx.fillStyle = `rgba(8,185,139,${glow})`;
        ctx.arc(p.x, p.y, p.r * 2.2, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.fillStyle = `rgba(200,230,220,${alpha * 0.35})`;
        ctx.arc(p.x - p.r * 0.25, p.y - p.r * 0.25, p.r * 0.35, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.fillStyle = `rgba(8,185,139,${alpha})`;
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }

      raf = requestAnimationFrame(tick);
    };

    const startLoop = () => {
      if (raf || !visible) return;
      raf = requestAnimationFrame(tick);
    };

    startLoop();

    return () => {
      stopLoop();
      ro.disconnect();
      document.removeEventListener("visibilitychange", onVis);
      mqMobile.removeEventListener("change", resize);
    };
  }, [reduced]);

  if (reduced) {
    return (
      <div
        className={className}
        aria-hidden
        style={{
          background:
            "radial-gradient(ellipse at 30% 20%, rgba(8,185,139,0.12), transparent 55%)",
        }}
      />
    );
  }

  return (
    <canvas
      ref={canvasRef}
      className={className}
      aria-hidden
      width={300}
      height={300}
    />
  );
}
