# ENG-002B2A: Common Engine Dual Runtime Fixture

- Status: Implemented
- Contract versions:
  - `pajin.dev/common-engine-runtime-coordinate/v1alpha1`
  - `pajin.dev/common-engine-runtime-execution/v1alpha1`
  - `pajin.dev/common-engine-dual-runtime/v1alpha1`
- Decision: [ADR-0106](../adr/0106-seal-dual-runtime-sources-before-behavioral-parity.md)

## Scope

ENG-002B2A creates the sealed source evidence required for full ENG-002 behavioral parity. It takes
one complete ENG-002B1 Planner parity authority and executes two independently fresh Runs: the
legacy-direct arm and the Profile-adapter arm. Both arms use the same Campaign semantics and exact
runtime component coordinate, while their physical output roots and all generated identities remain
independent.

This checkpoint deliberately does not normalize or compare Capability grants, Policy decisions,
Worker receipts, Validator Outcomes, or Mode-specific post-processing. It cannot compile a
`MissionEnvelope` or authorize Common execution.

## Runtime fixture coordinate

`CommonEngineRuntimeFixtureCoordinate` binds each arm to:

- the complete ENG-002B1 authority and the arm-specific typed Planner constructor;
- the exact current Validator class and, for AI assessment, its deterministic delegate and KISA
  candidate producer;
- `MultiAgentCampaignRunner` and its fixed parallelism;
- a canonical ordered set of `CommonEngineToolRuntimeBinding` records, each joining the complete
  `ToolSpec` to the explicit stable execution context of the Tool implementation;
- the explicit Policy stable execution context;
- the typed Worker evidence scope and the Worker's explicit stable execution context; and
- the semantic output role `common-engine-parity-fixture`.

The semantic coordinate digest excludes only the arm path and the arm-specific Planner constructor
path/digest. The physical output path is not authority: each arm must write to a separate root so
one Run cannot overwrite or inherit the other. Exact Tool Registry membership must equal the
ToolRequest set measured by ENG-002B1.

Stable contexts are converted to deterministic JSON. Mappings are key-sorted, ordered sequences
retain order, and set-like values are sorted by their canonical JSON representation. Non-finite
numbers, non-string mapping keys, and non-JSON values fail closed.

## Sealed execution records

Each `CommonEngineRuntimeExecutionRecord` requires:

- a completed `MultiAgentRunOutcome`;
- successful verification of the sealed Run root;
- a runtime Plan that normalizes to the exact ENG-002B1 observation for that arm;
- unique Tool request identities; and
- unique sealed evidence references.

`CommonEngineDualRuntimeExecutionAuthority` then requires the two records to have the same semantic
coordinate but disjoint Run, ToolRequest, and evidence identities. It binds both sealed root digests
and the complete B1 authority into a content-addressed record. This proves that the parity inputs
exist as two fresh, independently sealed executions; it does not prove that their behavior is equal.

## Negative cases

Construction or validation rejects:

- a Tool Registry with missing or additional tools;
- a ToolSpec detached from the implementation context that executes it;
- Validator, AI delegate, candidate producer, Policy, Worker, or Tool context drift between arms;
- a runtime Plan that differs from the B1 measurement;
- an incomplete, unsealed, or non-completed Run;
- duplicate or cross-arm Run, request, or evidence identity;
- digest or evidence substitution; and
- any parity, Envelope, or Common-execution authority escalation.

Coordinate drift is detected before either Worker is invoked. Once execution starts, a failed or
incomplete arm produces no dual authority.

## Compatibility, migration, and rollback

The API is additive, async, direct-call, and opt-in. Existing CLI/API paths, Mode runtimes, artifact
wire formats, and readers are unchanged. Rollback removes the B2A coordinate, execution schemas,
and harness while retaining ENG-002B1 and every legacy path.

ENG-002B2B must consume this exact dual authority and both verified Run trees. It may normalize only
explicitly enumerated fresh identities and timestamps, must compare Capability attenuation, Policy
and Worker receipts, Validator Outcome, and Mode post-processing, and must keep Envelope and Common
execution eligibility false for incomplete or different evidence.
