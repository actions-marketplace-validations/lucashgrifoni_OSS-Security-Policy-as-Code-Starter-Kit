import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(__dirname, "..", "dist");
const indexHtml = path.join(dist, "index.html");

if (!fs.existsSync(indexHtml)) {
  console.error("postbuild-pages: dist/index.html not found. Run vite build first.");
  process.exit(1);
}

fs.copyFileSync(indexHtml, path.join(dist, "404.html"));
console.log("postbuild-pages: wrote dist/404.html for GitHub Pages SPA routing.");
