# ADR-0129: Bind CAP-002 Compilation Before GRAPH Authority

- Status: Accepted
- Date: 2026-08-05

## Context

PERMIT-001 binds complete general attack meaning without creating a `ToolRequest`. CAP-002 already
owns exact code-backed Materializer and Action Compiler interfaces, complete seven-role authority
sets, adapter identity digests, and invocation wrappers that prevent a compiler from changing the
request identity, Agent, Target, method, Tool, or materialized arguments.

Several later types already contain compiled requests, but each carries authority that this
checkpoint does not possess. `PreparedCapabilityAction` requires a signed release and activation
set. `CommonEngineActionIntent` requires a Common Engine gate, release, MissionEnvelope, and budget
reservation. GRAPH-006 `ActionProposal` requires a current Graph Decision and Snapshot, run-level
Envelope, registered execution Capability, and reservation and is immediately adjacent to atomic
single-use Permit consumption. Replay compilation creates Replay-specific Grant and session
authority.

Reusing any of those as a generic PERMIT-002 result would either claim authority that was not
verified or collapse the proposal, compiler, Graph, budget, and Permit roles.

## Decision

Add one `GeneralAttackCompiledIntent` and one deterministic compiler with these rules:

1. Exact-rebuild PERMIT-001 from the complete current Campaign, ORCH, and CAP-001 source set before
   invoking code-backed roles.
2. Resolve one caller-supplied exact `CodeBackedCapabilityRef` through the complete CAP-002
   Registry. Do not discover, import, or select a latest compiler by name.
3. Reuse the existing `CapabilityAuthorityBinding`, canonical `ToolRequest`, Gateway request digest,
   and normalized-parameter digest contracts.
4. Derive a fresh request identity from the source proposal and selected authority identities,
   rather than reuse the earlier ORCH Specialist request ID.
5. Reopen Target and Tool from current trusted sources. Invoke only Materializer and Action Compiler
   once each.
6. Require the Materializer output to equal the source arguments as canonical JSON bytes and the
   compiler output to equal the complete code-owned seed request the same way. Boolean, integer,
   and float types remain distinct. Default insertion is expansion in this contract; a future
   normalization policy requires a separately versioned decision.
7. Re-resolve the complete seven-role authority set after both calls, before publishing output.
   Registry resolution requires two consecutive full observations, each role must preserve its
   declared identity while stable context is captured, and a final context-free declared-identity
   sweep rejects late scalar drift. Registered stable-context providers are code-owned trusted
   components and must be deterministic and side-effect-free; this boundary does not claim to
   sandbox Byzantine in-process adapter code.
8. Bind the complete source proposal, authority-set reference, selected adapter bindings, request,
   and existing digests into a content-addressed output with an external exact-rebuild verifier.
9. Keep release, activation, Grant, MissionEnvelope, Graph Decision, reservation, GRAPH proposal,
   Permit, dispatch, and execution absent and literally false.

## Consequences

- General attack semantics pass through registered code without letting model output or adapter
  normalization widen Target, method, Tool, or arguments.
- JSON scalar-type substitutions and observable cross-role authority drift are rejected at the
  compilation checkpoint rather than inheriting Python's loose numeric equality or a start-only
  registry view.
- Compiler rotation changes both the request and intent identities because authority-set and role
  digests are inputs.
- The compiled `ToolRequest` remains unusable without later Capability, Graph, budget, and Permit
  authority.
- Expected evidence, risk, side effects, and cleanup remain committed by PERMIT-001 but no
  post-result role is invoked early.
- PERMIT-003 has a narrow but non-trivial task: intersect this intent with release/activation,
  run-level Envelope, external current Graph Decision, and trusted reservation inputs before using
  GRAPH-006.

## Rejected alternatives

### Reuse `PreparedCapabilityAction`

Rejected for this checkpoint because its release, activation-set digest, and GRAPH Capability
reference assert CAP-004/005 authority not supplied by PERMIT-002. It remains the reference flow
for a later activation bridge.

### Reuse `CommonEngineActionIntent`

Rejected because it binds a different C2 gate, measured request, signed release, Envelope, and
reservation lineage.

### Construct GRAPH-006 `ActionProposal`

Rejected because no current Graph Decision, Snapshot, run-level MissionEnvelope, or trusted cost
authority is available. Creating an Envelope per action would also split durable budget accounting
across Envelope IDs.

### Permit arbitrary Materializer normalization

Rejected because CAP-002 bounds canonical JSON but does not define whether inserted defaults,
renamed keys, or other transformations narrow or widen a PERMIT-001 action. Exact equality is the
smallest reviewable rule.

## Compatibility and rollback

All schemas and public APIs are additive. Existing PERMIT-001, Capability, Replay, Common Engine,
GRAPH, Gateway, and Worker wires are unchanged. CAP-002 acceptance is intentionally stricter for
JSON-type-distinct compiler arguments and ordered identity drift. No persistent migration is
introduced. Rollback may remove the new API while retaining that generic CAP-002 correctness
hardening; retained compiled intents remain non-executable historical records and grant no
compatibility path into GRAPH-006.

## Related documents

- [PERMIT-002 contract](../orchestration/PERMIT-002-deterministic-action-compiler.md)
- [PERMIT-001 contract](../orchestration/PERMIT-001-general-attack-action-proposal.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0052: Code-backed Capability Authority Set](0052-code-backed-capability-authority-set.md)
