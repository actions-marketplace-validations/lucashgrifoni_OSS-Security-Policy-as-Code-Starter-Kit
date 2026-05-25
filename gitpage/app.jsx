// App entry — composes all sections

function App() {
  return (
    <div className="relative">
      <AmbientBackground />
      <SiteHeader />
      <main className="relative z-10">
        <Hero />
        <StatsStrip />
        <ProblemSection />
        <ComparisonSection />
        <ScopeSection />
        <ProfilesMarquee />
        <WorkflowSection />
        <SampleOutputSection />
        <QuickstartSection />
        <CapabilitiesSection />
        <FrameworksSection />
        <ControlCatalogSection />
        <EvaluationStatesSection />
        <DifferentiatorsSection />
        <SignalsSection />
        <CTASection />
        <SiteFooter />
      </main>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
