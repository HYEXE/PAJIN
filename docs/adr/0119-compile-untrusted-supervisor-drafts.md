# ADR-0119: Compile Untrusted Supervisor Drafts into Content-Free Advisory Proposals

- Status: Accepted
- Date: 2026-08-04

## Context

SUP-001 binds the raw WALK-006 and Collaboration Snapshot schemas plus an untrusted output draft,
and SUP-002 creates a separate taint-preserving `SupervisorSnapshotInput` projection wrapper. The
actual projection wrapper schema is not the same as the raw `CollaborationSnapshot` schema. Quietly
changing the SUP-001 v1alpha1 two-schema wire would invalidate its existing content identity, while
leaving the wrapper unbound at the proposal boundary would permit schema and taint drift.

The SUP-001 draft contains bounded model rationale and one of four roadmap kinds. Neither rationale
nor target-derived Snapshot text can choose Scope, arguments, Capabilities, Permits, or executable
objects. The current Collaboration projection also does not contain a trusted typed lifecycle
state from which a narrower semantic allowlist could be inferred.

## Decision

1. Add a separate deterministic SUP-003 compilation policy and typed proposal wire without
   changing SUP-001 or SUP-002 wire formats.
2. Bind the actual `SupervisorSnapshotInput` schema, the exact SUP-001 draft schema, the complete
   typed output schema, and the registered WALK-006 policy in the compiler policy.
3. Fix the current policy state to `current-collaboration-shadow` and allow exactly the four
   roadmap kinds. Do not derive policy state from Fact text or model rationale.
4. Reverify the complete SUP-002 input against current Campaign, Provider/model/configuration,
   Collaboration Snapshot, Graph, and Artifact authorities inside the compiler.
5. Require the draft Snapshot identity to equal the source Collaboration Snapshot while separately
   binding the complete SUP-002 input and its domain-separated taint digest.
6. Preserve the full draft and rationale only by digest and byte count. Do not copy their text into
   the typed output.
7. Emit one code-owned discriminated advisory payload per kind, with all application, mutation,
   scheduling, Scope, Capability, Permit, execution, notification, and activation effects false.
8. Treat the input draft only as syntactically conforming untrusted data. Do not claim a Provider
   response, model-output attestation, invocation receipt, or model quality.
9. Reject Pydantic boolean/integer coercion on all new authority fields and close the same numeric
   boolean coercion in the adjacent WALK-006 Stop and authority wires.
10. Require a versioned additive invocation binding before any future model call uses the actual
    SUP-002 projection wire. SUP-003 schema binding is a compiler boundary, not invocation
    authority.

## Consequences

- Prompt-shaped target content and rationale can change source digests but cannot become executable
  fields or code-selected semantics.
- A valid foreign or stale input remains unusable because compilation repeats the external current
  authority verification.
- The four proposal forms are measurable structural recommendations, not TaskGraph, Plan, Stop,
  escalation, Capability, Permit, or execution records.
- SUP-001 v1alpha1 compatibility is preserved, but its raw input-schema list is not sufficient for
  a future Provider request. SUP-004 must resolve that invocation boundary before calling a model.
- Numeric `0`/`1` encodings that previously passed WALK-006 boolean validation now fail closed;
  canonical valid JSON booleans are unchanged.

## Compatibility and rollback

SUP-003 is additive and has no runtime wiring or stored-state migration. Existing public readers,
CLI inputs, Provider sessions, Snapshot wires, TaskGraph, Capability, Permit, and execution paths
are unchanged. Rollback removes the compiler and typed proposal API. The WALK-006 coercion hardening
can remain as a compatible rejection of invalid wire values.

## Related documents

- [SUP-003 contract](../orchestration/SUP-003-typed-non-executable-supervisor-proposal.md)
- [SUP-002 contract](../orchestration/SUP-002-snapshot-only-target-taint-input.md)
- [SUP-001 contract](../orchestration/SUP-001-supervisor-model-binding.md)
- [ADR-0118](0118-preserve-target-taint-in-supervisor-snapshot-input.md)
- [ADR-0117](0117-bind-shadow-supervisor-model-before-invocation.md)
- [WALK-006 contract](../orchestration/WALK-006-shadow-supervisor-decision-record.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
