# ADR-0125: Bind Benchmark Coordinates into Supervisor Provider Requests

- Status: Accepted
- Date: 2026-08-05

## Context

SUP-005A proves that an actual SUP-004B3 proposal and BENCH-003B2 share the WALK-006 policy, but it
correctly refuses to attribute the existing numeric deltas to that model call. BENCH-003B2's
candidate is a static policy, its fixture reports zero model calls, and B3 has no Benchmark arm,
seed, repetition, or Target coordinate.

A post-hoc sidecar from a completed receipt to a caller-selected coordinate would permit replay,
cross-coordinate substitution, and cherry-picking. Putting a raw caller digest into the generic B3
stable-request preimage would also hide external meaning from the journal and receipt. The complete
typed context must exist, be sealed, and be inspectable before the actual ToolRequest is made.

## Decision

1. Derive a fresh two-arm Manifest from the exact BENCH-003B2 structural baseline. Do not relabel or
   reuse its numeric Results.
2. Define one static candidate implementation digest over the SUP-001 binding, registered SUP-003
   compiler, SUP-004 budget, and request/response schemas. Keep per-coordinate state outside it.
3. Seal the complete Cartesian coordinate set and a one-to-one mapping from every candidate
   coordinate to an exact SUP-004A schedule in a non-executable Campaign Plan.
4. Treat that Plan as a mapping only. It does not prove dispatch absence or authorize invocation.
5. Define a typed benchmark request assertion over the Plan publication, complete set, coordinate,
   and schedule. Store it in new explicit `v1alpha2` B3 intent and receipt wires; the generic B3
   receipt does not itself attest that the referenced Plan is sealed.
6. Include the typed context digest in the stable Provider request ID so the actual Gateway
   ToolRequest, reservation, Provider outcome, evidence, and receipt share the same identity.
7. Preserve context-free B3 calls byte-for-byte at `v1alpha1`; omit the optional context field and
   use the existing stable-request v1 preimage.
8. Require an exact B3 invoker and reconsume the terminal journal, two-seal Run, receipt, SUP-003
   proposal, Plan envelope, and all predecessor sources before admitting a benchmark candidate;
   never trust the typed assertion or returned wrapper by itself.
9. Keep numeric comparison, causal proposal attribution, threshold evaluation, execution, and
   activation false until externally adjudicated observations exist for the complete two-arm set.

## Consequences

- A candidate Provider request has an inspectable, content-addressed Plan/coordinate context before
  dispatch, and exact retries reproduce only that context.
- A foreign Plan or coordinate changes the stable request ID and is rejected as checkpoint
  equivocation by the durable journal.
- The Plan can be created independently of dispatch, but only the verified invocation wrapper
  proves its seal preceded dispatch.
- Existing Benchmark aggregation, Target/Harness lifecycle, B3 database schema, and context-free
  artifacts are not duplicated or migrated.
- Actual model-backed numeric effectiveness remains unmeasured until SUP-005B2 supplies externally
  adjudicated observations.

## Compatibility and rollback

The Plan and request-context contracts are additive. The B3 intent and receipt use explicit
`v1alpha2` only when a benchmark context is present; legacy `v1alpha1` serialization and request
identity remain unchanged. Rollback removes the new caller and leaves context-bound Runs as sealed,
non-activating evidence. A pre-existing context-bound journal entry remains terminal or
outcome-unknown under the existing no-redispatch rule.

## Related documents

- [SUP-005B1 contract](../orchestration/SUP-005B1-sealed-benchmark-campaign-request-context.md)
- [SUP-005A contract](../orchestration/SUP-005A-source-bound-deterministic-baseline-lineage.md)
- [SUP-004B3 contract](../orchestration/SUP-004B3-durable-supervisor-invocation-receipt.md)
- [ADR-0124: Non-attributed benchmark lineage](0124-bind-supervisor-proposals-to-benchmark-lineage-without-attribution.md)
- [ADR-0123: Durable Supervisor invocation](0123-durably-claim-and-seal-supervisor-invocations.md)
