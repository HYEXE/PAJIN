# P0-E3A Single-Agent Baseline Plan

## Status

Implemented as a non-runnable `v1alpha1` contract and measurement plan. No concrete agent runtime,
Provider registration, model revision, prompt bundle, tool catalog, invocation receipt, raw trace,
normalized Observation, or Benchmark Result is claimed.

## Goal and trust boundary

PAJIN has a governed model Provider port and a Provider-backed multi-role runtime, plus deterministic
test adapters. None of those is a benchmark identity for one model-backed agent. The multi-role
runtime creates Planner, Specialist, Validator, and Reporter roles; the local PydanticAI adapter
accepts only the deterministic `TestModel`; test Provider workers synthesize responses. Treating any
of these as a measured single-agent baseline would invent the missing runtime and evidence boundary.

P0-E3A therefore fixes the identity, no-fallback execution, raw-trace, Target, and coordinate facts
that P0-E3B must prove before execution. It does not choose a vendor, endpoint, model, credential,
price, prompt, or tool catalog.

## Versioned authorities

| Authority | API version | Role |
| --- | --- | --- |
| `GenericSingleAgentAdapterContract` | `pajin.dev/generic-single-agent-adapter-contract/v1alpha1` | Required agent/Provider/model/prompt/tool/runtime identity and raw-trace policy |
| `SingleAgentBaselineCoordinate` | `pajin.dev/single-agent-baseline-coordinate/v1alpha1` | One exact Manifest arm, seed, and repetition |
| `SingleAgentBaselineMeasurementPlanAuthority` | `pajin.dev/single-agent-baseline-measurement-plan/v1alpha1` | Exact P0-D1 Target selection, generic single-agent contract, and complete coordinates |

Every authority rejects unknown fields and uses bounded domain-separated canonical digests.

## Invariants

1. The Manifest contains exactly one non-adaptive baseline arm using the code-owned generic
   single-agent implementation ID/version/configuration digest.
2. `deterministic-baseline` is the existing BENCH-001 non-adaptive baseline arm classification; it
   does not claim deterministic model output. Seeds, repetitions, and run-to-run variance remain
   mandatory for a future model-backed Result.
3. The Manifest has no mutation profile, no adaptive candidate, and at least one model-call and one
   target-Tool-call budget.
4. The existing P0-D1 selector reconstructs the exact Manifest, adapter, Docker profile, catalog,
   and private Ground Truth before plan creation.
5. The plan binds every protocol seed/repetition coordinate exactly once in canonical order.
6. A runnable registration must bind agent implementation ID/version/digest, Provider registration
   digest, exact model revision, prompt-bundle digest, tool-catalog digest, and runtime-configuration
   digest.
7. Model access is only through a registered Provider Gateway; Target access is only through
   approved Tools in fresh Target isolation.
8. Fallback is disabled. A model refusal, transport failure, invalid output, or exhausted budget
   cannot be replaced by deterministic output in a baseline Result.
9. Raw evidence uses `pajin-model-tool-trace-jsonl/v1`, requires model request/result, tool
   request/receipt/result, Provider usage, and cleanup events, forbids secret values, and is retained
   before normalization.
10. All concrete identity, execution, trace, Result, comparison, and Supervisor activation flags
    are literal `false` in P0-E3A.

## Required rejection behavior

- additional arms, adaptive candidate, mutation, or zero model-call budget;
- unregistered implementation/configuration or changed trace-parser semantics;
- alternate Target profile, catalog, adapter, or private Ground Truth;
- missing, duplicate, extra, or reordered coordinates;
- reordered or incomplete required identity fields;
- injected Provider endpoint, model, credential reference, prompt, tool, trace, or Result data; and
- attempts to promote any execution, binding, Result, comparison, or activation flag.

## Compatibility and rollback

The implementation adds opt-in contracts and exports only. Existing Provider, agent, Target,
P0-E1/P0-E2, BENCH-003, and Result wire formats do not change. Rollback removes the P0-E3A plan
types; it cannot invalidate or reinterpret a measured artifact because P0-E3A creates none.

## Next runnable boundary

P0-E3B must select a concrete agent implementation and Provider/model artifact, bind exact prompts,
tools, sampling/runtime configuration and trusted pricing, disable fallback, execute every coordinate
inside fresh P0-D1 isolation, seal raw traces and Provider usage, and pass recovery, cleanup, catalog,
and registry-governed admission before emitting a completed `BenchmarkResult`.

## References

- [BENCH-001 contract](BENCH-001-benchmark-contract.md)
- [P0-E2B Scanner measurement](P0-E2B-zap-scanner-baseline-measurement.md)
- [ADR-0009 Provider runtime](../adr/0009-provider-backed-agent-runtime.md)
- [ADR-0098](../adr/0098-bind-single-agent-identity-before-measurement.md)
