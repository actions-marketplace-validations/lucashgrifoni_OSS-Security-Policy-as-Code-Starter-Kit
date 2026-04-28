import { lazy, Suspense } from "react";
import { AmbientBackground } from "./components/layout/AmbientBackground";
import { MainSectionsFallback } from "./components/layout/MainSectionsFallback";
import { SiteFooter } from "./components/layout/SiteFooter";
import { SiteHeader } from "./components/layout/SiteHeader";
import { HeroSection } from "./sections/HeroSection";

const BelowFoldSections = lazy(async () => {
  const m = await import("./BelowFoldSections");
  return { default: m.BelowFoldSections };
});

export default function App() {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-ink text-mist">
      <a
        href="#hero"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[100] focus:rounded-lg focus:bg-signal focus:px-4 focus:py-2 focus:text-ink"
      >
        Skip to content
      </a>
      <AmbientBackground />
      <SiteHeader />
      <main>
        <HeroSection />
        <Suspense fallback={<MainSectionsFallback />}>
          <BelowFoldSections />
        </Suspense>
      </main>
      <SiteFooter />
    </div>
  );
}
