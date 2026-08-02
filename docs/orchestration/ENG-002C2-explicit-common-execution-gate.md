# ENG-002C2: Explicit Common Execution Gate

- Status: Implemented
- Contract versions:
  - `pajin.dev/common-engine-execution-gate-compiler/v1alpha1`
  - `pajin.dev/common-engine-execution-gate-authority/v1alpha1`
  - `pajin.dev/common-engine-action-intent/v1alpha1`
- Decision: [ADR-0109](../adr/0109-activate-common-execution-with-a-separate-compiler.md)

## Scope

ENG-002C2 is the first explicit opt-in bridge from a complete ENG-002C1 authority into the existing
GRAPH-006 atomic `ActionPermit` and CAP-005 Tool Gateway dispatch path. It does not add another
Permit store, Capability registry, Gateway, Policy engine, or Worker path. Legacy Mode execution
remains the default and no CLI, API, or automatic adapter selection calls this module.

C1's compiler explicitly forbids Permit issuance and Common dispatch. C2 does not reinterpret or
flip those fields. `CommonEngineExecutionGateAuthority` introduces a separate code-owned execution
compiler and derives a new `MissionEnvelope` whose Campaign, Run, Profile, source Campaign,
Capability set, target set, risk, budget, rate, autonomy, and authorization fields are exactly the
C1 Envelope. Only compiler identity and the resulting Envelope content address differ.

## Explicit activation authority

`compile_common_engine_execution_gate_authority()` requires a canonical C1 authority and a current
verified CAP-005 activation exactly equal to the C1 activation set. Every C1 request binding's
Capability and signed release are resolved again before the gate authority is created.

The execution compiler fixes:

- `sourceEnvelopeScopeMutationAllowed=false`;
- `actionPermitIssuanceAuthorized=true`;
- `commonRuntimeDispatchAuthorized=true`; and
- `legacyDefaultPathSelectionAuthorized=false`.

The gate authority embeds the C1 authority, exact activation set, source Envelope digest, new
compiler, and new Envelope. Its reader reconstructs the C1 authority and executable Envelope and
requires exact equality. `legacyDefaultPathChanged=false` is mandatory.

## Action intent and fresh request identity

One non-executable `CommonEngineActionIntent` is compiled for one exact C1 Capability binding and a
caller-declared fixed-point micro-USD reservation no larger than the Envelope ceiling. The intent
binds both C1 and C2 authority digests, Envelope, binding, activation set, signed release,
Capability, measured request digest, execution request, request/parameter/target digests, and exact
GRAPH reservation.

B2B measurement intentionally uses fixture request IDs, while the GRAPH-006 SQLite ledger requires
request IDs to be globally unique within a Campaign database. C2 derives the execution request ID
from the C1 Run ID and exact binding digest under a code-owned domain. Tool, agent, target, method,
and arguments remain byte-for-byte canonical equivalents of the measured request. The same Run and
binding produce the same ID for exact retry; a different Run produces a different ID.

The intent is `requested-not-permitted`: `explicitOptIn=true`, `actionPermitIssued=false`, and
`commonRuntimeDispatched=false`. It becomes eligible only when a `GraphDecision` of kind
`action-proposal` binds the exact intent digest and latest immutable Graph Snapshot.

## Dispatch sequence

`CommonEngineExecutionGate.dispatch_once()` performs the following order:

1. reload the C2 authority, intent, Graph Decision, Campaign, and Capability Grant canonically;
2. reconstruct the expected intent from C2 and require exact equality;
3. require the current activation set, Campaign, audit Run, decision payload, Snapshot Campaign,
   decision time, and Grant authority to cover the exact action;
4. rerun CAP-002 materialization and signed release resolution for the execution request;
5. build an `ActionProposal` from the exact intent and Graph Decision actor;
6. reuse `GraphActionPermitAuthority` to reproject the durable Event Log, require the latest
   Snapshot, enforce durable budget/rate limits, and atomically consume one Permit; and
7. reuse `ExistingModeCapabilityGatewayDispatcher` to record claimed/terminal Run events,
   revalidate the release immediately before Gateway entry, and invoke the existing Gateway.

One gate object pins one C2 authority and claims the existing Permit writer once. Exact retry
therefore reconstructs the same Proposal and Permit, returns `dispatched=false`, and never calls the
Worker again. Permit or Gateway failures retain the existing GRAPH-006/CAP-005 safety-first terminal
semantics; a consumed Permit is never automatically redispatched.

## Negative cases

Activation or dispatch fails closed for:

- C1/C2/compiler/Envelope/activation-set substitution or executable-envelope field expansion;
- inactive, foreign, or drifted signed Capability release;
- intent binding, request, parameter, target, Capability, reservation, or flag forgery;
- foreign Campaign, Run audit store, Graph Decision payload, Snapshot, or actor lineage;
- stale Graph projection or non-latest Snapshot;
- Grant subject, Campaign, Tool, target, risk, call capacity, or time under-authorization;
- Proposal, Permit, request, or Capability mismatch at the reused authorities;
- durable count, request-unit, micro-USD, or rolling-rate exhaustion; and
- exact retry, request identity collision, or concurrent duplicate claim attempts that are not the
  one durable first consumption.

## Compatibility, migration, and rollback

The APIs are additive, direct-call, and module-only at
`pajin.workflow.engine_execution_gate`. The package initializer is unchanged to avoid the existing
Capability replay import cycle. Existing C1, MissionEnvelope, Graph, Capability, Campaign, Mode,
CLI, artifact, Policy, Gateway, and Worker wire formats are unchanged.

The tested vertical slice executes the CTF Profile through the existing real contract Worker path;
the gate code has no Mode branch and consumes the C1 bindings already proven for all three legacy
Modes. Removing the C2 module and callers disables Common execution without invalidating C1 or any
legacy path.

The caller remains responsible for supplying a trusted current activation, durable latest Graph,
RunStore matching the C1 Run, Gateway dependencies, and an authorized Capability Grant. The cost
reservation is caller-declared and decision-bound; it is not a claim of measured provider cost.
The underlying local SQLite Graph and process-local activated registry boundaries remain unchanged.
