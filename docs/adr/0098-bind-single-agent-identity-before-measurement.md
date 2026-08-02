# ADR-0098: Bind Single-Agent Identity Before Claiming Measurement

## Status

Accepted.

## Context

P0-E3 asks for a single-agent baseline. The repository has governed Provider transport and a
Provider-backed multi-role runtime, but no authority that identifies one agent implementation,
exact model revision, prompt bundle, tool catalog, runtime configuration, no-fallback policy, and
raw model/tool trace as one benchmark implementation. Existing test Provider workers and
PydanticAI `TestModel` are deterministic fixtures, not measured external model providers.

Choosing a vendor or replaying synthetic Provider responses inside P0-E3 would silently decide
cost, credentials, supply-chain identity, data handling, and model-output semantics while claiming
a real baseline.

## Decision

1. Split P0-E3 into P0-E3A contract planning and P0-E3B runnable measurement.
2. Define a code-owned generic single-agent contract that requires exact agent implementation,
   Provider registration, model revision, prompt bundle, tool catalog, and runtime configuration.
3. Require registered Provider Gateway access and approved Target Tools; direct SDK/network access
   is not a benchmark path.
4. Require one model-backed agent with deterministic fallback disabled. Failure or refusal remains
   failure and cannot become a deterministic baseline observation.
5. Require a raw, secret-free, bounded model/tool trace before normalization, including Provider
   usage and cleanup evidence.
6. Bind the existing P0-D1 selection and complete seed/repetition set to one non-adaptive baseline
   arm with positive model-call and Target-Tool-call budgets.
7. Treat the existing `deterministic-baseline` arm value as the non-adaptive baseline category, not
   a claim that model output is deterministic; repetitions and variance remain required.
8. Do not select a concrete Provider/model, endpoint, secret reference, prompt, tool catalog,
   executable, pricing schedule, or trace artifact in P0-E3A.
9. Fix every concrete identity, execution, trace, Result, comparison, and Supervisor activation
   flag to false.

## Consequences

- A fake Provider response, deterministic `TestModel`, or PAJIN multi-role Run cannot be relabeled as
  the single-agent baseline.
- P0-E3B has an explicit checklist for reproducible identity, costs, raw evidence, and failure
  semantics before any Result is eligible.
- The current Provider and agent runtimes remain unchanged and reusable inputs to a future adapter.
- A concrete vendor/model and its external data/cost policy remain an explicit later decision.

## Compatibility and rollback

The change is additive and non-executable. Rollback removes the new plan types and leaves all prior
Provider, agent, benchmark, and Target artifacts unchanged.

## References

- [P0-E3A contract](../benchmark/P0-E3A-single-agent-baseline-plan.md)
- [ADR-0009](0009-provider-backed-agent-runtime.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [P0-E2B contract](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
