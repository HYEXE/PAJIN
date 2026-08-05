# ADR-0124: Bind Supervisor Proposals to Benchmark Lineage Without Attribution

- Status: Accepted
- Date: 2026-08-05

## Context

SUP-004B3 provides the first actual model-backed Shadow Supervisor proposal. BENCH-003B2 provides
an exact numeric comparison whose candidate is the code-owned WALK-006 policy. The two sources
share that policy, but they are not the same implementation or measurement coordinate. B3 binds a
Provider, model configuration, Collaboration Snapshot, request, journal, and receipt but has no
Benchmark Manifest, arm, seed, repetition, or target coordinate. BENCH-003B2 does not identify a
B3 invocation and its current fixture reports zero model calls. Attaching its deltas to a completed
B3 proposal would invent causal evidence.

## Decision

1. Add a versioned SUP-005A authority that re-verifies one terminal B3 source and one sealed
   BENCH-003B2 source and binds their exact provenance.
2. Recompute the SUP-003 proposal only through `consume_supervisor_invocation()`; never accept a
   standalone proposal as source authority.
3. Reuse the existing BENCH-003B2 Result, Comparison, metric order, and WALK-006 policy, and harden
   the B2 reader to require its exact sealed publication envelope. Do not copy or recompute numeric
   values.
4. Require the exact code-owned WALK-006 policy on both sources while preserving their different
   domain-separated Campaign digests and verifying one common `CampaignManifest` through both
   predecessor readers.
5. Persist digest-only B3 receipt provenance and the content-free typed proposal. Do not copy raw
   draft, rationale, prompt, response, secret, or Worker transcript.
6. Record that the policy comparison exists but model-proposal measurement attribution, benchmark
   coordinate binding, threshold evaluation, model-backed eligibility, execution, and activation
   are all false.
7. Require a later pre-invocation coordinate authority and B3-backed external observations before
   any numeric comparison can be attributed to the model-backed candidate.
8. Require both readers to reconstruct the exact seal count, artifact set, ordered event payloads,
   and strict unambiguous Run record; integrity-valid foreign envelope content must fail closed.

## Consequences

- Operators can trace a live B3 proposal to the exact policy-level baseline/candidate comparison
  without confusing shared policy lineage with measured model effectiveness.
- Existing BENCH-003 calculations remain the only metric authority and cannot be cherry-picked or
  rewritten by SUP-005A.
- The output makes the missing benchmark coordinate and model-call observation explicit instead
  of silently treating them as satisfied.
- SUP-005A cannot decide rollout thresholds or activate the Supervisor.
- Exact retries have stable content identity but may publish duplicate sealed Runs because no new
  durable publication registry is introduced.

## Compatibility and rollback

The authority, runner, and reader are additive direct-module APIs. Existing Supervisor, Walking,
Benchmark, Provider, Graph, and artifact wires are unchanged. No migration is needed. Rollback
removes the new path and preserves its sealed records as non-executable audit evidence.

## Related documents

- [SUP-005A contract](../orchestration/SUP-005A-source-bound-deterministic-baseline-lineage.md)
- [SUP-004B3 contract](../orchestration/SUP-004B3-durable-supervisor-invocation-receipt.md)
- [BENCH-003B2 contract](../benchmark/BENCH-003B2-walking-shadow-policy-binding.md)
- [ADR-0123: Durable Supervisor Invocation](0123-durably-claim-and-seal-supervisor-invocations.md)
- [ADR-0080: Shadow Policy-Bound Measurement](0080-shadow-policy-bound-measured-benchmark.md)
