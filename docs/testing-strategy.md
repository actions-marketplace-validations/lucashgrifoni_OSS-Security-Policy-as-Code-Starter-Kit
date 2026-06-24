# Testing Strategy

## Layers

1. **Unit** (`tests/unit/`) - fast, deterministic checks for isolated behavior.
2. **Application** (`tests/application/`) - engine, evaluators, reporting, profile drift, and contracts.
3. **CLI** (`tests/cli/`) - subcommand behavior, flags, error handling, and compatibility surfaces.
4. **Infrastructure** (`tests/infrastructure/`) - workflow, packaging, and CI/CD structure checks.
5. **Integration** (`tests/integration/`) - end-to-end behavior against representative local fixtures.
6. **Property** (`tests/property/`) - Hypothesis-generated inputs for invariants and edge cases.

## Property-Based Testing

Property tests catch edge cases that example-based tests are unlikely to enumerate. Current coverage:

- Waiver expiry semantics across past, future, datetime-shaped, and invalid date strings.
- ProfileSpec loading for generated external profile YAML.
- ControlSpec catalog loading across assurance, lifecycle, and weight combinations.
- EvalOutcome JSON roundtrip for every status and evidence collection method.
- Evaluation report schema roundtrip for the `reports/2.0` contract (the only contract since v9.0.0).
- Evaluator invariants across the **entire** `EVALUATOR_REGISTRY` (`test_evaluator_invariants.py`): for synthetic repositories with random file present/absent combinations, every `eval_*` returns an `EvalOutcome` (never raises), with a valid `ControlStatus`, a list of string `evidence_sources`, deterministic results on an identical context, and no writes to the target repository.

The `reports/2.0` serialization (`report_to_dict_v2_0`) is validated against the `reports/2.0` JSON schema in `tests/property/test_report_schema_roundtrip.py`, with roundtrip invariants (no control lost, every status in the five-state vocabulary, run metadata preserved). The legacy pre-2.0 contracts and their migration tests were removed in v9.0.0 (ADR-043); the offline `scripts/migrate-1.0-to-2.0.py` converter remains for previously stored `1.0` reports.

Run locally:

```bash
python -m pytest tests/property/
```

Run with Hypothesis statistics:

```bash
python -m pytest tests/property/ --hypothesis-show-statistics
```

## Guardrails

- Property tests must stay deterministic enough for CI; use bounded `max_examples` and `deadline=None` for engine-level tests.
- Generated inputs should assert concrete invariants, not only non-null outputs.
- Network, cloud, registry, Docker daemon, and live GitHub API calls stay out of property tests.
- When Hypothesis finds a counterexample, add a focused regression test if the behavior is security-sensitive or user-visible.
