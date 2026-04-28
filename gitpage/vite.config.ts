import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Set VITE_BASE to your repo subpath for GitHub Project Pages, e.g. /oss-policy-kit/
export default defineConfig({
  plugins: [react()],
  base: process.env.VITE_BASE ?? "/",
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/framer-motion")) return "motion";
        },
      },
    },
  },
});
