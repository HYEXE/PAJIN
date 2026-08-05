# ADR-0126: Bind B3 Completions into Externally Attested Target Execution

- Status: Accepted
- Date: 2026-08-05

## Context

SUP-005B1 binds an exact Benchmark coordinate into the actual B3 ToolRequest before dispatch, but
it produces no numeric measurement. The existing P0-C Harness signs Target lifecycle receipts and
the external Observation, while BENCH-003B1 already owns complete-set aggregation and numeric
Comparison.

Joining an independently completed B3 receipt and Target Observation only by coordinate and
overlapping timestamps would remain a post-hoc sidecar. A caller could choose among multiple
otherwise valid Target Runs for the same coordinate. Creating another Observation or Comparison
schema would duplicate existing authority and could allow proposal-derived values to bypass the
external adjudicator.

## Decision

1. Invoke the exact SUP-005B1 candidate inside the Target execution window.
2. Build a typed, domain-separated relation over the Plan, coordinate, request context, journal,
   Provider Run, receipt, Provider outcome, proposal, and raw Target provider-evidence digest.
3. Place that relation digest in the Target execution receipt's `providerEvidenceDigest`. The
   existing external measurement attestation then signs the relation transitively without a P0-C
   wire change.
4. Preserve the underlying Target evidence digest inside the typed relation rather than replacing
   or discarding it.
5. Reopen every Plan, B3, Target, registry admission, signed activation, Harness, and Observation
   through its existing public reader. Require complete coordinates, one exact registry revision,
   fresh source identities, baseline zero model calls, and candidate exactly one model call.
6. Require signed execution start and completion to contain the journal dispatch and terminal
   timestamps.
7. Pass only verified Harness Observation outcomes to the existing BENCH-003B1 runner. Do not call
   the generic Observation recorder and do not construct Results, metrics, or Comparison directly.
   Before sealing and on every read, require the BENCH-003B1 Observation bindings to equal the
   registry-governed Target Run, root, artifact SHA-256, and complete Observation set.
8. Seal one digest-only SUP-005B2 lineage authority referencing the existing Comparison Run.
9. Keep proposal causal attribution, threshold eligibility, activation, and execution false.

## Consequences

- The existing external measurement key explicitly attests the B3-to-Target execution relation.
- A valid B3 receipt cannot be attached later to another Target Run unless the measurement
  authority signs a different relation and execution receipt.
- Numeric values remain owned by external Target adjudication and BENCH-003B1.
- B3 charged cost is a conservative upper bound, while Observation cost is a coordinate-total
  measurement; the authority records their distinct meanings without equating them.
- The implementation adds lineage records only and preserves every predecessor wire.

## Compatibility and rollback

This decision is additive. Existing context-free and context-bound B3, Target, Harness,
Observation, Result, and Comparison readers remain unchanged. Rollback removes the SUP-005B2
admission path and leaves all sealed predecessor evidence independently readable. No completed
Comparison grants activation authority.

## Related documents

- [SUP-005B2 contract](../orchestration/SUP-005B2-registry-governed-model-backed-comparison.md)
- [SUP-005B1 contract](../orchestration/SUP-005B1-sealed-benchmark-campaign-request-context.md)
- [SUP-004B3 contract](../orchestration/SUP-004B3-durable-supervisor-invocation-receipt.md)
- [BENCH-003B1 contract](../benchmark/BENCH-003B1-walking-measurement-admission.md)
- [P0-C2B2A2 contract](../benchmark/P0-C2B2A2-mandatory-registry-governed-harness.md)
- [ADR-0125: Benchmark coordinate request binding](0125-bind-benchmark-coordinates-into-supervisor-provider-requests.md)
- [ADR-0085: Mandatory registry-governed Harness](0085-mandatory-registry-governed-benchmark-harness.md)
