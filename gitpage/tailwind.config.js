/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0c124c",
        mist: "#d5d8dd",
        signal: "#08b98b",
        steel: "#5a6876",
        slate: "#7c8394",
      },
      fontFamily: {
        sans: [
          "var(--font-sans)",
          "ui-sans-serif",
          "system-ui",
          "Segoe UI",
          "sans-serif",
        ],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      backgroundImage: {
        "radial-signal":
          "radial-gradient(ellipse 80% 60% at 50% -20%, rgba(8,185,139,0.35), transparent 55%)",
        "radial-ink":
          "radial-gradient(ellipse 100% 80% at 100% 0%, rgba(124,131,148,0.12), transparent 50%)",
        "mesh-premium":
          "linear-gradient(135deg, rgba(8,185,139,0.08) 0%, transparent 40%), linear-gradient(225deg, rgba(12,18,76,0.9) 0%, #0c124c 45%, #0a0f3a 100%)",
      },
      boxShadow: {
        glow: "0 0 60px -12px rgba(8, 185, 139, 0.45)",
        "glow-sm": "0 0 32px -8px rgba(8, 185, 139, 0.35)",
        panel: "0 25px 80px -20px rgba(0, 0, 0, 0.55)",
      },
      animation: {
        "pulse-slow": "pulse-slow 6s ease-in-out infinite",
        drift: "drift 18s ease-in-out infinite",
        scan: "scan 8s linear infinite",
        "hero-shimmer": "hero-shimmer 5s ease-in-out infinite",
      },
      keyframes: {
        "pulse-slow": {
          "0%, 100%": { opacity: "0.5" },
          "50%": { opacity: "1" },
        },
        drift: {
          "0%, 100%": { transform: "translate(0, 0) scale(1)" },
          "33%": { transform: "translate(2%, -1%) scale(1.02)" },
          "66%": { transform: "translate(-1%, 2%) scale(0.98)" },
        },
        scan: {
          "0%": { backgroundPosition: "0% 0%" },
          "100%": { backgroundPosition: "200% 0%" },
        },
        "hero-shimmer": {
          "0%, 100%": { opacity: "0.2", transform: "translateX(-40%) scaleX(0.6)" },
          "50%": { opacity: "0.95", transform: "translateX(40%) scaleX(1)" },
        },
      },
    },
  },
  plugins: [],
};
