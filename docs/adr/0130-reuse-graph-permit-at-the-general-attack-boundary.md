# ADR-0130: Reuse GRAPH Permit at the General Attack Boundary

- Status: Accepted
- Date: 2026-08-05

## Context

PERMIT-002 produces an exact deterministic `ToolRequest`, but intentionally carries no signed
release, activation, GRAPH Capability, run-level Envelope, Graph Decision, reservation,
`ActionProposal`, Permit, or execution authority. CAP-004/005 already own signed release currency
and opt-in activation. GRAPH-006 already owns the run-level `MissionEnvelope`, exact
`ActionProposal`, latest-Snapshot validation, durable budget accounting, atomic consumed Permit,
and first-consumption dispatcher.

Creating another Permit-shaped bridge or pre-issuing a Permit would split the single-consumption
authority. Reusing a Common Engine action intent would import unrelated C1/C2 profile and measured
request lineage. Calling the CAP-005 Gateway dispatcher now would also cross into SUP-007 product
execution and require Grant and Run-audit composition not owned by PERMIT-003.

Three general-attack authorities are not yet implemented as generic repository services: a
verified run-level Envelope producer, a Graph Decision actor/provenance registry, and a trusted
micro-USD pricing authority. `MissionEnvelope`, `GraphDecision`, and `ActionBudgetReservation` are
canonical self-binding values, not proof that their producer is trusted. Accepting arbitrary
instances would turn caller input into Capability, target, actor, or budget authority.

## Decision

Add one direct-call `GeneralAttackActionPermitGate` with these rules:

1. Exact-rebuild the current PERMIT-002 intent from all PERMIT-001, ORCH, CAP-001, and CAP-002
   sources before considering execution-adjacent authority.
2. Match exactly one existing CAP-005 activation binding by the intent's complete
   `CodeBackedCapabilityRef`. Revalidate its current signed release before and after CAP-002
   `prepare_action()` and exact-match the prepared request and all existing digests.
3. Resolve the CAP-001 Definition independently from the source Registry and activated rollout;
   they must be equal.
4. Require an injected `GeneralAttackActionPermitInputAuthority`. It is the external composition
   trust root for a pre-existing run-level Envelope, authenticated Graph Decision actor/provenance,
   and trusted fixed-point integer cost. Pass it canonical deep-detached copies of the verified
   intent, prepared action, Campaign, and Definition so provider mutation cannot alter gate-owned
   predecessor authority. Its result is in-process only; do not create a new persisted or
   self-authenticating authority wire.
5. Independently intersect the provider outputs with current Campaign authorization, testing
   window, duration, autonomy, risk, Tool-call/cost/rate ceilings, exact Capability, target,
   Definition request-unit cost, and Envelope budget. Derive request units from the activated
   Definition and construct the existing reservation inside the gate.
   Require an action-proposal Decision whose payload digest is the current intent and propagate the
   proposer only from that Decision actor.
6. Re-resolve signed activation after the external provider returns, then derive the existing
   GRAPH-006 `ActionProposal` from verified values only.
7. Reuse the existing activation registry, `GraphActionPermitAuthority`, SQLite Permit store, and
   `GraphActionPermitDispatcher`. Bind the existing authority to a Campaign-aware claim clock so
   authorization and testing-window currency are checked at the same final time passed to SQLite.
   One gate pins one exact Envelope and activation set and claims one existing writer identity.
8. Reject synchronous callbacks before any claim and consume a Permit only when a coroutine
   function or async callable is present at the dispatch boundary. Pass
   that callback the consumed Permit, exact current prepared action, and derived GRAPH proposal.
   Exact retry never invokes the callback twice; callback failure is terminal under GRAPH-006.
9. Do not call Gateway, Worker, Success Oracle, Replay, Cleanup, or Executor code and do not wire the
   gate into a default Campaign workflow.

## Consequences

- PERMIT-003 reaches durable exact single-use authority without duplicating GRAPH state, schema,
  budget accounting, concurrency, crash, or retry semantics.
- A changed source, activation, Decision, Envelope, target, request, Campaign ceiling, expired
  testing window, provider predecessor mutation, or cost fails before a consumer callback. Stale
  Graph state fails inside the existing final SQLite transaction.
- The deterministic PERMIT-002 request ID remains Campaign-database-wide single use. A different
  Envelope or Decision cannot re-authorize an already consumed request.
- The external input authority is an explicit trusted computing-base dependency. PERMIT-003 proves
  intersection and exact propagation; it does not claim to cryptographically authenticate an
  incorrect provider implementation.
- There is intentionally no built-in general-attack Envelope, Decision, or pricing provider yet.
  The API remains disconnected until a deployment supplies one and SUP-007 composes Grant, audit,
  Gateway, and Worker authority.
- PERMIT-004 remains the owner of side-effect, data-flow, Oracle, and cleanup authority.

## Rejected alternatives

### Accept raw Envelope, Decision, and cost values

Rejected because canonical digests prove internal identity, not producer provenance. In particular,
GRAPH-006 does not interpret Decision kind/payload/actor semantics or compare
`sourceCampaignDigest` with a current Campaign or attenuate authorization, duration, autonomy,
risk, Tool-call, cost, or rolling-rate ceilings.

### Add a general-attack Permit or consumed-request store

Rejected because it would create two final authorities and lose GRAPH-006's single SQLite
transaction, durable collision checks, and first-consumption semantics.

### Pre-issue an unused Permit

Rejected because GRAPH-006 Permits are consumed on issuance. Pre-minting would burn the request
before SUP-007 could dispatch it and would tempt callers to treat the record as a bearer token.

### Reuse the Common Engine execution gate

Rejected because its C1/C2 compilation, profile parity, measured request, and mission binding are
different predecessor authorities. Its assembly pattern is reused, not its authority record.

### Call the CAP-005 Gateway dispatcher now

Rejected because that would require current Grant and Run-audit authority and would collapse the
PERMIT-003 Permit checkpoint into SUP-007 product execution.

## Compatibility and rollback

All additions are module-level and in-process. Existing wire versions, SQLite schema, public
imports, readers, Campaign defaults, Common Engine, Replay, Gateway, and Worker behavior remain
unchanged. Rollback removes the gate and callers; already consumed GRAPH Permits remain immutable
and cannot be replayed.

## Related documents

- [PERMIT-003 contract](../orchestration/PERMIT-003-exact-single-use-action-permit.md)
- [PERMIT-002 contract](../orchestration/PERMIT-002-deterministic-action-compiler.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [ADR-0047: MissionEnvelope and ActionPermit Algebra](0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0109: Activate Common Execution with a Separate Compiler](0109-activate-common-execution-with-a-separate-compiler.md)
