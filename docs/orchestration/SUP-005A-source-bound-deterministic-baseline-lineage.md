# SUP-005A: Source-Bound Deterministic Baseline Lineage

- Status: Implemented
- Authority contract: `pajin.dev/supervisor-deterministic-baseline-lineage/v1alpha1`
- Runtime boundary: `SupervisorDeterministicBaselineLineageRunner.run()`
- Decision: [ADR-0124](../adr/0124-bind-supervisor-proposals-to-benchmark-lineage-without-attribution.md)

## Scope

SUP-005A is the first honest bridge between one actual SUP-004B3 invocation and the existing
BENCH-003 policy measurement. It re-consumes the terminal B3 journal, schedule, two-seal receipt,
and current SUP-003 proposal, independently reloads one sealed BENCH-003B2 authority, and records
that both sources use the same code-owned WALK-006 policy.

This authority does not say that BENCH-003 measured the B3 Provider call or proposal. B3 has no
Benchmark Manifest, arm, seed, repetition, or `BenchmarkTargetCoordinate`, while BENCH-003B2 binds
its candidate to the static WALK-006 policy only. Assigning its numeric deltas to B3 would be a
cross-implementation substitution. The output therefore fixes model attribution, model-backed
comparison eligibility, threshold evaluation, execution, and activation to false.

## Exact source verification

The runner accepts no standalone proposal or caller-supplied metric projection. It calls
`consume_supervisor_invocation()` again with the current journal, schedule, Campaign, Snapshot,
model binding, Provider, and Graph authorities. The recomputed content-free proposal must exactly
equal the supplied B3 completion. It then calls
`load_walking_shadow_measured_benchmark_authority()` for BENCH-003B2 and requires the exact
code-owned WALK-006 policy ID, version, and digest on both sides.

The B3 lineage records:

- immutable journal intent, terminal state, three event digests, and dispatch event digest;
- schedule, checkpoint, request binding, response schema, and dedicated budget identities;
- stable request and Provider Run identities plus the final root;
- receipt path, SHA-256, ID, digest, Provider outcome, and dual budget scope;
- source Snapshot and model binding identities; and
- the content-free SUP-003 proposal, compilation policy, kind, ID, and digest.

The BENCH-003B2 lineage records:

- B2 output Run, root, artifact path, SHA-256, authority ID, and digest;
- embedded BENCH-003A and BENCH-003B1 authority identities;
- Manifest, baseline/candidate arms, WALK-006 policy, Results, and Comparison digests; and
- candidate coordinate count and the model-call count actually reported by the sealed raw
  observations.

The authority stores all twelve canonical metric names in order but does not copy values or deltas.
Those remain authoritative only in BENCH-003B1/B2. Domain-specific Campaign digests are preserved
separately: the SUP-001/Profile digest and WALK-006 Campaign digest need not be equal, while both
loaders receive and verify the same exact `CampaignManifest` whose detached digest is also bound.

Both the hardened B2 reader and the SUP-005A reader require one seal, their exact three-artifact
set, the exact ordered three-event sequence and full payloads, and the complete expected
`run.json`. Run records are parsed as strict unambiguous JSON, so duplicate keys cannot turn a
foreign state into the expected state by last-value-wins parsing.

## Output state

The output state is exactly `structural-source-bound-not-model-measured` with:

- `samePolicyLineageVerified=true`;
- `policyBenchmarkComparisonAvailable=true`;
- `modelProposalMeasurementAttributed=false`;
- `benchmarkCoordinateBoundToInvocation=false`;
- `modelBackedBenchmarkEligible=false`;
- `thresholdEvaluationEligible=false`; and
- `supervisorActivationEligible=false`.

Task creation, Plan mutation, Scope expansion, baseline mutation, Capability, Permit, execution,
and activation remain false. The output includes no B3 raw draft, rationale text, prompt, Provider
response, secret, Worker transcript, or BENCH-003 metric value.

## Negative boundaries

Creation or reload fails closed for:

- stale or foreign B3 journal, schedule, request, receipt, Run root, Snapshot, model binding,
  Provider outcome, or typed proposal;
- unsealed, mutated, foreign-Campaign, or foreign-policy BENCH-003B2 sources;
- validly resealed predecessor or output envelopes with extra artifacts/events, changed start or
  completion payloads, foreign Run state, or duplicate JSON keys;
- source Run/root/artifact substitution, proposal or policy digest forgery, metric-name omission or
  reordering, integer/count coercion, and boolean authority coercion;
- copying metric values or raw model content into the new wire; and
- any attempt to claim benchmark coordinates, model-caused improvement, threshold eligibility,
  execution, or activation.

Exact retries derive the same authority identity but may create another sealed publication Run.
SUP-005A does not introduce a durable publish-once registry.

## Compatibility, migration, and rollback

The module and v1alpha1 wire are additive. SUP-001 through SUP-004B3, WALK-006, BENCH-003A/B1/B2,
Benchmark Result/Comparison, Provider, Graph, and RunStore wires remain unchanged. No artifact or
database migration is required. Rollback removes the additive runner and retains its sealed Runs as
non-executable audit evidence.

## Next boundary

SUP-005B must create an exact candidate implementation and `BenchmarkTargetCoordinate` binding
before model dispatch, link every candidate seed/repetition to its B3 schedule, journal, receipt,
and proposal, and produce B1-compatible externally adjudicated observations. Only a complete
two-arm coordinate set may reuse the existing canonical `BenchmarkComparison`; activation remains
false.
