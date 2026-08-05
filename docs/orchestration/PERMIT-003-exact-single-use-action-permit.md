# PERMIT-003: Exact Single-use General Attack ActionPermit

- Status: Implemented
- Runtime API: `pajin.supervision.GeneralAttackActionPermitGate`
- Decision: [ADR-0130](../adr/0130-reuse-graph-permit-at-the-general-attack-boundary.md)

## Scope

PERMIT-003 is the smallest bridge from the non-executable PERMIT-002
`GeneralAttackCompiledIntent` to the existing GRAPH-006 atomic single-use `ActionPermit` path. It
does not define another Envelope, Graph proposal, Permit, store, dispatcher, consumed-request
ledger, or execution runtime.

The bridge exact-rebuilds every PERMIT-002 predecessor, revalidates the current signed CAP-004/005
release and activation, re-runs CAP-002 request preparation, intersects the result with one
pre-existing run-level `MissionEnvelope`, one externally authenticated current `GraphDecision`,
and one trusted fixed-point micro-USD cost, then derives the existing GRAPH-006 reservation and
`ActionProposal`. The existing SQLite Permit transaction is the only final authority.

## External input authority

PAJIN does not yet have a general-attack run-level Envelope producer, Graph Decision provenance
registry, or generic pricing service. Treating a self-digested model or arbitrary caller integer as
proof would manufacture authority. PERMIT-003 therefore requires an injected
`GeneralAttackActionPermitInputAuthority` at composition time.

That code-owned or externally backed authority must:

1. authenticate a pre-existing run-level `MissionEnvelope` and return the exact current value;
2. authenticate the external `GraphDecision`, including actor identity and provenance; and
3. derive an exact integer micro-USD value from a trusted pricing or conservative reservation
   policy. The provider cannot choose request units; the gate reads them from the current activated
   CAP-001 Definition and constructs the existing `ActionBudgetReservation` itself.

The authority returns an in-process `GeneralAttackActionPermitInputs` value. It receives canonical
deep-detached copies of the verified intent, prepared action, Campaign, and Definition; mutating
those advisory copies cannot change the gate-owned authorities used for Proposal construction or
the callback. It is a trust-root interface, not a serializable attestation, signed record, or
alternate Permit authority. No default implementation is registered and no legacy workflow calls
this gate. A deployment must supply an appropriate implementation before it can opt into this
direct API.

PERMIT-003 does not blindly accept those outputs. It canonicalizes them and independently requires
Campaign, source Campaign digest, authorization/testing window, duration, autonomy, Capability,
target, risk, Tool-call/cost/rate ceiling, request-unit cost,
Decision kind, payload, Snapshot Campaign, and exact actor-to-proposer propagation to agree with
the current sources and existing authorities.

## Dispatch sequence

`GeneralAttackActionPermitGate.dispatch_once()` performs this order:

1. canonicalize the current Campaign and invoke `verify_general_attack_compiled_intent()` with the
   complete PERMIT-001, ORCH, CAP-001, and CAP-002 source set;
2. find exactly one active CAP-005 binding whose `CodeBackedCapabilityRef` equals the compiled
   intent;
3. call `resolve_for_dispatch()` and `prepare_action()` through the current signed release, then
   re-resolve the release and exact-match activation-set, release, GRAPH Capability, request,
   request digest, normalized-parameter digest, and canonical request bytes;
4. resolve the CAP-001 Definition from both the current compiler Registry and activated rollout and
   require exact equality;
5. give the external input authority canonical deep-detached predecessor copies and ask it for its
   existing Envelope, Decision, and strict integer cost;
6. require current Campaign authorization and testing window, constrain Envelope authorization and
   duration inside the Campaign, require exact Campaign autonomy, and attenuate risk, Tool-call,
   fixed-point cost, and rolling-rate ceilings;
7. derive request units only from the current activated CAP-001 Definition, construct the existing
   reservation, and intersect the exact activated Capability, target digest, risk, and reservation
   with the Envelope;
8. require `decisionKind=action-proposal`, `decisionPayloadDigest` equal to the exact PERMIT-002
   intent digest, matching Campaign/Snapshot, an in-window timestamp, and copy proposer identity
   only from the authenticated Decision actor;
9. re-resolve the signed activation after the external authority call, then derive the existing
   `pajin.dev/action-proposal/v1alpha2` value without caller-controlled request
   or authority fields; and
10. give the existing `GraphActionPermitAuthority` a Campaign-aware claim clock that rechecks the
   current authorization and testing window at the same final time passed to SQLite, then use the
   existing `GraphActionPermitDispatcher` so latest-Graph validation, durable cumulative and rolling
   budget accounting, request/proposal collision checks, and consumed Permit insertion occur in the
   existing SQLite transaction before the callback.

One gate instance pins one exact Envelope digest and activation-set digest and claims the existing
Permit writer once. An exact retry reconstructs the same Proposal and Permit, returns
`dispatched=false`, and never calls the consumer again. A changed Envelope must use another
composition boundary and cannot be substituted into an already-bound gate.

## Consumption and execution boundary

GRAPH-006 consumes a Permit when the dispatch claim commits. PERMIT-003 therefore never pre-mints
or returns an unused bearer Permit. It requires a coroutine function or async callable before any
claim and invokes it only for the transaction's first consumption. The callback receives the
consumed Permit plus the exact
current `PreparedCapabilityAction` and derived `ActionProposal`; downstream code does not need to
reconstruct request material from a stale caller closure. Callback failure remains terminal under
the existing safety-first GRAPH contract; automatic redispatch is forbidden.

The new gate does not itself call `ToolGateway`, a Worker, CAP-002 Success Oracle, Replay Strategy,
Cleanup Handler, or Executor Adapter. Tests use a counting callback only to prove first-consumption
semantics. SUP-007 must provide the explicit product composition that connects this callback to an
authorized Gateway path, including the existing Grant and Run audit requirements. PERMIT-004A now
requires a deployment input authority to resolve the Run, pre-claim audit anchor, and exact Grant;
then authenticates the resulting sealed no-write lifecycle and `worker.dispatched` job before
Oracle, bounded data-flow observation, or Cleanup Handler use.

## Negative boundaries

The gate fails closed before Permit consumption for:

- stale, foreign, substituted, or self-consistently forged PERMIT-001/002, ORCH, CAP-001, or CAP-002
  source authority;
- absent, ambiguous, foreign, drifted, or inactive signed release and activation;
- CAP-002 re-preparation changes to request ID, Agent, Tool, Target, method, arguments, request
  digest, normalized-parameter digest, or scalar JSON type;
- foreign or forged Campaign digest, Envelope Campaign, Capability, target, risk, timeline, or
  budget ceiling;
- expired Campaign authorization, inactive testing window, excessive Envelope duration, autonomy
  escalation, or wider Campaign risk, Tool-call, fixed-point cost, or rolling-rate ceiling;
- non-action, foreign-payload, foreign-Campaign, or out-of-window Graph Decisions;
- non-integer trusted cost inputs, external authority operational failure or attempted predecessor
  mutation, or request-unit values not derived from the exact current CAP-001 Definition;
- micro-USD or other reservations above the run-level Envelope ceiling;
- another Envelope or activation set substituted after one gate has been bound; and
- a synchronous callback, signed activation drift during external input resolution, or a Campaign
  testing window that closes while the external authority resolves its inputs.

The reused SQLite transaction rejects a stale or unreconciled Graph, non-latest Snapshot, durable
budget/rate exhaustion, request/proposal equivocation, cross-Envelope request replay, and concurrent
double consumption. Existing GRAPH-006 tests remain the authority for crash, recovery, and
cross-process concurrency semantics; PERMIT-003 adds bridge-specific stale-Graph and exact-retry
coverage rather than duplicating that implementation.

## Compatibility, migration, and rollback

The module and package exports are additive and direct-call only. PERMIT-001/002, CAP-001 through
CAP-005, GRAPH-006, Common Engine, Replay, Campaign, Gateway, Worker, artifact, CLI, and persistent
wire formats are unchanged. No database schema or artifact migration is introduced.

Rollback removes the new gate, exports, tests, and callers. Existing consumed GRAPH Permits remain
valid immutable audit records and are not reinterpreted. Removing the gate cannot make a consumed
request dispatchable again.

## Remaining boundary

PERMIT-004A binds current Success Oracle, side-effect ceiling, bounded transport observation, and
Cleanup Handler to a completed Permit-bound sealed no-write result. PERMIT-004B must add a separate
typed cleanup request, one-shot cleanup Permit, and aggregate Campaign budget accounting before
write or cleanup-required actions are admitted. SUP-007 must later supply an explicit T0/T1 product
composition with a deployment-owned Run resolver, current Grant, Run audit, Gateway, Worker, and
outcome-gate authorities. Until that checkpoint, PERMIT-003 is an available authority bridge but
not a default execution path.

## Related documents

- [PERMIT-002 contract](PERMIT-002-deterministic-action-compiler.md)
- [PERMIT-004A contract](PERMIT-004A-authenticated-action-outcome-gate.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [CAP-004 contract](../capability/CAP-004-maturity-signing-review-deprecation.md)
- [CAP-005 contract](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
