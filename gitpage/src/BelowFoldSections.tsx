import { CapabilitiesSection } from "./sections/CapabilitiesSection";
import { ControlExamplesSection } from "./sections/ControlExamplesSection";
import { CTASection } from "./sections/CTASection";
import { DifferentiatorsSection } from "./sections/DifferentiatorsSection";
import { EvaluationStatesSection } from "./sections/EvaluationStatesSection";
import { FrameworksSection } from "./sections/FrameworksSection";
import { HowItWorksSection } from "./sections/HowItWorksSection";
import { ProblemSection } from "./sections/ProblemSection";
import { QuickstartSection } from "./sections/QuickstartSection";
import { RepoStructureSection } from "./sections/RepoStructureSection";
import { RoadmapSection } from "./sections/RoadmapSection";
import { ScopeSection } from "./sections/ScopeSection";

/**
 * All main sections below the hero, loaded as a single async chunk to reduce initial JS parse.
 */
export function BelowFoldSections() {
  return (
    <>
      <ProblemSection />
      <ScopeSection />
      <HowItWorksSection />
      <QuickstartSection />
      <CapabilitiesSection />
      <FrameworksSection />
      <EvaluationStatesSection />
      <DifferentiatorsSection />
      <ControlExamplesSection />
      <RoadmapSection />
      <RepoStructureSection />
      <CTASection />
    </>
  );
}
