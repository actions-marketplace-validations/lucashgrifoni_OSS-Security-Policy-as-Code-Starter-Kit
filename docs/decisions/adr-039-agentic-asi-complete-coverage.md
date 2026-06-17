# ADR-039 - Complete OWASP Agentic ASI coverage (ASI05/08/10 low-confidence signals)

- **Status**: accepted
- **Date**: 2026-06-16
- **Context window**: v10 additive slice (loop-runner build)
- **Related**: revises ADR-024 (OWASP Agentic ASI, partial coverage), ADR-016 (`ai-agent-baseline-1`), ADR-023 (MCP)

## Context

ADR-024 shipped five signal-grade `AGENT-ASI-*` controls (ASI01, ASI02, ASI06, ASI07,
ASI09) and **explicitly rejected** covering all ten, stating that the rest "need runtime
telemetry the kit cannot observe" (ADR-024, Alternative 1).

On re-evaluation that claim is too strong for three of the remaining risks: each has a
**documentable, clone-visible posture signal** — not runtime observation. The kit never
executes the agent; it pattern-matches a documented control posture and reports it at low
confidence, consistent with the existing five.

## Decision

Add three `AGENT-ASI-*` controls so ASI01-ASI10 is fully mapped, all source-side, all
low-confidence signals (never verdicts):

- `AGENT-ASI-EXEC-005` (ASI05) — documented code-execution sandbox / isolation posture
  (seccomp, gVisor, container, WASM). The kit does not run the interpreter.
- `AGENT-ASI-CASCADE-008` (ASI08) — documented iteration/recursion/step caps or circuit
  breakers on agent loops. The kit does not prove the guard is wired at runtime.
- `AGENT-ASI-ROGUE-010` (ASI10) — documented agent inventory / registry / monitoring;
  complements `AI-AGENT-007` (tool-call audit).

ASI03 and ASI04 remain **mapped, not duplicated**: ASI03 → `AI-AGENT-008`, ASI04 →
`AI-AGENT-010` / `MCP-TOOL-HASH-001`. All three new controls return `NOT_APPLICABLE` when no
agentic framework is detected and `MANUAL_REVIEW_REQUIRED` (not `FAIL`) when applicable but
no signal is found. Bundled in `appsec-agentic-asi-1`. Advisory; `--fail-on degraded`.

## Alternatives considered

1. **Keep ADR-024's partial coverage.** Rejected — the three signals are genuinely
   clone-visible (documented posture, not runtime telemetry), and adopters asked for the full
   ASI01-10 map. This ADR supersedes ADR-024 Alternative 1 on that point.
2. **Implement them as runtime checks.** Rejected — violates the clone-only architecture; the
   kit never executes the agent.
3. **Raise their confidence to match deterministic controls.** Rejected — keyword/posture
   matching is inherently weak; they stay `confidence="low"` and honest about it.

## Consequences

- Agent authors get a complete clone-visible OWASP Agentic ASI01-10 hygiene baseline.
- Honesty preserved: low-confidence signals, `MANUAL_REVIEW_REQUIRED` when absent,
  `NOT_APPLICABLE` when no agentic framework — no inflation of pass/fail.
- ADR-024 stays valid for the original five; this ADR records the deliberate revision of its
  rejected alternative so the change is traceable, not silent.

## References

- OWASP Top 10 for Agentic Applications (2026), ASI01-ASI10
- ADR-024 (OWASP Agentic ASI); ADR-016; ADR-023
