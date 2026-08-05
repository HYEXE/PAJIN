# SUP-005B2: Registry-Governed Model-Backed Comparison

- Status: Implemented
- Candidate execution evidence: `pajin.dev/supervisor-benchmark-candidate-execution-evidence/v1alpha1`
- Measured comparison authority: `pajin.dev/supervisor-benchmark-measured-comparison/v1alpha1`
- Decision: [ADR-0126](../adr/0126-bind-b3-completions-into-externally-attested-target-execution.md)

## Scope

SUP-005B2 completes the first measured model-backed Shadow comparison without creating another
Observation, Result, Comparison, registry, or Target store. It accepts only the fresh two-arm
Manifest sealed by SUP-005B1, exact context-bound B3 candidate completions, and outcomes from the
existing registry-governed Benchmark Harness. The existing BENCH-003B1 runner remains the only
numeric aggregation and Comparison authority.

The candidate proposal stays content-free and non-executable. Finding, Chain, Replay, Policy,
Human, time, call-count, and cost values come only from the external measurement authority's
Target Observation. No proposal field or rationale is converted into a metric.

## Candidate execution relation

A candidate Target adapter invokes `invoke_supervisor_benchmark_candidate()` inside its execution
window. It then constructs `SupervisorBenchmarkCandidateExecutionEvidence` over:

- the exact SUP-005B1 Plan and Benchmark coordinate;
- typed request-context and stable Gateway ToolRequest identity;
- terminal journal intent, dispatch event, dispatch and terminal timestamps;
- Provider Run/root, receipt, Provider outcome, and current SUP-003 proposal identities; and
- the adapter's raw Target provider-evidence digest.

The adapter places this typed relation digest in the Target execution receipt's
`providerEvidenceDigest`. The existing P0-C measurement attestation signs that receipt together
with the exact coordinate, lifecycle receipts, and Observation. The later Target, registry
admission, and Harness authorities bind the same receipt transitively. A timestamp-only or
coordinate-only post-hoc sidecar therefore cannot be admitted.

The raw Target evidence digest remains present inside the typed relation. The externally measured
coordinate-total cost is deliberately separate from B3's conservative charged upper bound; no
equality or arithmetic relationship is inferred between them.

## Complete-set admission

`SupervisorBenchmarkMeasuredComparisonRunner` independently reloads:

1. the complete SUP-005B1 Plan, Campaign, BENCH-003B2 predecessor, and every SUP-004A schedule;
2. every candidate through `verify_supervisor_benchmark_candidate_invocation()`;
3. every Target, fresh registry admission, durable signed activation, and Harness through the
   existing public readers; and
4. the complete BENCH-003B1 measured output through its existing public reader.

It requires exactly one Harness source per Plan coordinate and exactly one B3 relation per
candidate coordinate. Harness, Target, admission, Observation, execution receipt, stable request,
intent, Provider Run, receipt, and proposal identities must be fresh and unique. All coordinates
must use one exact registry activation and revision.

The deterministic baseline must externally report zero model calls. Every candidate must report
one model call, while its B3 charged usage also reports exactly one. The signed Target execution
window must contain B3 dispatch and terminal timestamps. The request cost and timeout upper bounds
must fit within the per-coordinate Benchmark protocol.

Only after these checks does the runner pass the existing sealed Observation outcomes to
`WalkingBenchmarkMeasuredComparisonRunner`. BENCH-003B1 then enforces the complete canonical
arm/seed/repetition set, one measurement authority, all twelve metrics, and fresh unique source
Runs before producing the two Results and canonical Comparison. Before sealing or re-admitting the
SUP-005B2 authority, every BENCH-003B1 Observation binding must also equal the corresponding
registry-governed Target Run ID, root, artifact path, artifact SHA-256, and complete Observation.
This prevents another otherwise valid generic or historical Comparison from being substituted.

## Output authority

`SupervisorBenchmarkMeasuredComparisonAuthority` stores digest-only lineage for the Plan, every
Harness/Target/attestation/Observation/execution relation, and the existing measured Comparison
Run. It does not copy raw Observation values, metric values, deltas, drafts, proposal rationale,
or external evidence bytes.

The completed authority fixes:

- `benchmarkCoordinateBoundToInvocation=true`;
- `externallyAttestedObservationSet=true`;
- `benchmarkComparisonEligible=true`;
- `proposalCausalEffectAttributed=false`;
- `thresholdEvaluationEligible=false`;
- `supervisorActivationEligible=false`; and
- `executionAuthorized=false`.

The Comparison measures the registered Shadow arm under the exact controlled Manifest. Because
the proposal is not applied to Target execution, it does not prove that proposal content caused an
improvement and cannot authorize activation.

## Fail-closed boundaries

Admission rejects:

- generic caller-recorded Observations, incomplete or duplicate coordinate sets, and old numeric
  Result reuse;
- cross-Plan, cross-coordinate, cross-arm, context-free, foreign schedule, or replayed B3 sources;
- a relation digest not present in the externally signed execution receipt;
- B3 dispatch or terminal time outside the signed Target execution window;
- baseline model calls, zero or multiple candidate model calls, and Benchmark request bounds that
  exceed the coordinate protocol;
- stale, mutated, foreign, or mixed Harness, Target, registry, activation, attestation, or
  Observation sources;
- reused stable request, intent, Provider Run, receipt, proposal, Target Run, or Observation; and
- boolean coercion or any attempt to claim proposal causality, threshold eligibility, activation,
  or execution authority.

## Compatibility and rollback

All SUP-004B3, SUP-005B1, P0-C, BENCH-003B1, Provider, Target, registry, Observation, Result, and
Comparison wires remain unchanged. The two SUP-005B2 records and one digest-only lineage Run are
additive. Rollback stops admitting new SUP-005B2 authorities; existing B3, Harness, Target, and
BENCH-003B1 Runs remain independently readable and non-activating.

## Completed successor boundary

This is a host-local, externally signed benchmark authority for the configured Target and
measurement registry. It does not prove distributed exactly-once execution, production model
quality, proposal causal effect, or activation thresholds. SUP-006 now applies an adversarial
prompt-injection corpus across this path while preserving the same taint, Scope, non-execution, and
activation-false boundaries. See the
[SUP-006 contract](SUP-006-adversarial-prompt-injection-regression.md).
