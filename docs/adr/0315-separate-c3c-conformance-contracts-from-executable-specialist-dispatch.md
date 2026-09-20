# ADR-0315: Separate C3C Conformance Contracts from Executable Specialist Dispatch

- Status: Adopted
- Date: 2026-09-18
- Scope: AGENTIC-003C specialist dispatch binding, Worker conformance, and the authority boundary for future executable dispatch
- Implementation status: Audit binding and Target-I/O-zero Worker contract foundations implemented; executable v2 dispatch pending

## Context

AGENTIC-003C follows the C3B2 crash fence, where an approved specialist plan is reserved and started under one-shot authority. The repository now has two C3C foundations:

1. a content-addressed specialist dispatch binding that records the exact started execution and preparation; and
2. a signed specialist Worker contract that proves a deterministic, network-disabled, Target-I/O-zero conformance job.

These foundations are deliberately narrower than executable specialist dispatch. The binding's serialized model is an audit artifact, not a bearer credential. Its live registry handle is process-local, one-shot, pinned to the exact Store authority and minting task, and cannot be reconstructed from serialized data. The Worker contract accepts only exact identity references, rejects route, payload, transport, catalog, and egress material, requests no secrets, disables networking, and asserts that no target I/O, production authority, independent validation, Finding, Graph, report, SARIF, or PoC work occurred.

The existing `agentic-web-specialist` v1 Capability and Tool are also intentionally inert and content-addressed. Their stable identity and fail-closed behavior are already part of the public security contract. Making v1 executable in place would change that identity's meaning.

The generic Tool Gateway resolves a Tool by Tool ID. Tool ID equality alone does not prove that a later Tool implementation is the exact version and digest approved by the Capability activation, Prepared Action, Grant, approval, and Permit. Planning with v1 and substituting an executable v2 Tool after Permit issuance would therefore cross the authorization boundary without a matching approval chain.

Executable dispatch also has state that cannot safely be represented by the audit binding. It needs the exact Store and database runtime, deployment instance, minting task, Campaign, Capability Grant and consumption evidence, activation, Prepared Action, approval, Permit, and current execution state. Serializing or rebuilding that state after process restart would manufacture authority from evidence that was never intended to be a bearer credential.

Finally, claiming a one-shot dispatch binding introduces lifecycle questions that the conformance foundation does not answer: when expiry and revocation become final, what happens if the owning task or deployment closes before backend dispatch, and how an ambiguous backend outcome is durably recorded without an unsafe retry.

## Decision

### 1. Keep the v1 Capability and Tool permanently inert

The current v1 Capability, Tool, activation validation, request identity, content-addressed artifacts, and fail-closed `prepare` and `interpret` behavior remain unchanged.

Executable dispatch will use a new v2 Capability and Tool contract. A v2 run must use the exact v2 Capability definition, activation, Prepared Capability Action, one-call Grant, approval, and Permit from the beginning of planning. An existing v1 plan, Grant, approval, Permit, or started execution cannot be upgraded by selecting a v2 Tool later, even when the Tool ID is unchanged.

The executable path must verify exact versions and content digests throughout the chain. Tool ID matching is necessary for routing but is not sufficient authorization.

### 2. Separate the audit binding from the live authority capsule

The content-addressed specialist dispatch binding remains a detached audit model. It may describe exact references, reservation state, source reservation state, and lifecycle evidence, but it has no serialized bearer authority and performs no target I/O.

Future executable dispatch must introduce a separate opaque live capsule. The capsule is bound to:

- the exact Store authority and database runtime;
- the exact deployment instance and backend inventory;
- the exact minting asynchronous task;
- the exact Campaign and current Graph head;
- the exact Capability definition, activation, Prepared Action, Grant, and Grant consumption evidence;
- the exact approval, Permit, preparation, started execution, and dispatch binding; and
- the exact Worker image, command, backend, and verifier configuration admitted by the deployment.

The live capsule must be private, non-copyable, non-serializable, and one-shot. It must not be exposed through the detached binding model or public artifact readers. Database rows, journal entries, binding JSON, receipts, or other audit artifacts cannot recreate it after process restart. A restart may recover audit state and classify an outcome, but it may not recover execution authority.

The registry must retain permanent terminal tombstones. In addition to successful completion, the executable lifecycle must support an explicit abandon operation for authority claimed while still safely before backend dispatch. Closing the owning task, Store, Gateway, deployment, or coordinator, cancellation, failed preflight, or failed current-state validation must abandon the claim. Abandonment records a terminal reason digest and never makes the binding available for rebind, retry, refund, or authority reconstruction.

### 3. Treat the current Worker contract as Target-I/O-zero conformance only

The current C3C Worker image and command remain a deterministic conformance contract:

- networking is disabled;
- no egress policy or secret request is admitted;
- input consists only of exact `{id, digest}` references for execution, binding, preparation, profile, executor, capability, tool, request, Permit, and Grant consumption;
- route, payload, transport, catalog, target, and egress material are rejected;
- the signed statement is verified against a deployment-owned Ed25519 verification key; and
- target I/O, backend execution, secret use, production eligibility, independent validation, Finding promotion, Graph admission, reporting, SARIF, and PoC production are all explicitly false.

This contract is evidence that the conformance job stayed within its zero-I/O boundary. It is not evidence that an isolated production Worker executed, and it cannot authorize target access. It does not provide a live Tool `prepare`/`interpret` path or a backend bridge.

The executable v2 path requires a separate Worker contract. Immediately before backend use, it must verify an immutable Worker image digest, exact command, exact backend identity, deployment inventory admission, and a deployment-pinned output verification key. A mutable image tag or a caller-selected verification key is insufficient.

### 4. Revalidate current authority at both execution boundaries

Successful planning and binding do not freeze external authority indefinitely. The executable coordinator must revalidate current state immediately before invoking the Tool Gateway and again immediately before the irreversible backend dispatch.

Those checks include, at minimum:

- the current Campaign scope and status;
- the current Graph head and admitted predecessor evidence;
- the current specialist profile and executor catalogs;
- the current deployment and backend inventory;
- the exact Capability, activation, Prepared Action, Tool, request, Grant consumption, approval, and Permit chain;
- expiry and revocation state for every time-bounded or revocable authority; and
- the exact live capsule, task, Store, database runtime, and registry ownership.

Any mismatch fails closed before target I/O. The generic Tool Gateway remains an enforcement layer, but its Tool-ID routing check cannot replace these exact-chain checks.

### 5. Define the post-claim linearization point and terminal receipt

The executable design must define one durable dispatch linearization point immediately before the backend can perform target I/O.

Before that point, expiry, revocation, scope change, catalog change, deployment change, cancellation, or owner closure terminates the attempt by abandoning the claimed authority. No backend call occurs.

At the linearization point, the coordinator must durably record the exact job digest, Worker image and verifier pins, current-state verification digest, and a `worker.dispatched` event before or atomically with handing control to the backend. Once the backend call may have begun, later expiry or revocation cannot retroactively make that dispatch unapproved, but it also cannot authorize another attempt.

Every claimed attempt must end in a durable terminal receipt. The receipt classifies at least:

- abandoned before backend dispatch;
- completed with a verified Worker output;
- failed before target I/O;
- failed after dispatch with a proven terminal backend result; or
- started with outcome unknown.

An outcome-unknown attempt is consumed authority. It cannot be treated as safely abandoned, automatically retried, refunded, reissued, or reconstructed after restart. Operator reconciliation may add evidence, but it cannot silently create a second dispatch.

### 6. Keep AGENTIC-003D outside C3C

C3C ends with dispatch authority enforcement and a cryptographically verified Worker receipt. Independent replay or validation, semantic oracle decisions, Finding promotion, Graph admission, attack-path expansion, report generation, SARIF, and redacted PoC production belong to AGENTIC-003D.

C3C Worker outputs must therefore remain ineligible for those promotions until 003D independently validates them under its own authority and provenance contracts. The conformance Worker's corresponding fields remain literal false.

## Consequences

### Positive

- Existing v1 identities retain their original inert meaning.
- A Permit cannot be widened by swapping in a different Tool implementation after approval.
- Audit artifacts remain useful without becoming replayable bearer credentials.
- Process, task, Store, database, deployment, and Worker authority are bound at the point where they matter.
- Expiry, revocation, cancellation, and closure have explicit fail-closed semantics after a claim.
- Ambiguous backend outcomes cannot cause automatic duplicate target actions.
- C3C and 003D retain independently reviewable trust boundaries.

### Tradeoffs and residual risks

- A started execution cannot resume executable authority after process restart; it must be reconciled from durable receipts and then terminated or classified.
- The executable coordinator needs more deployment-owned state and more current-state reads than the conformance foundation.
- The dispatch linearization write and backend handoff require careful failure classification because a fully atomic transaction may not span both systems.
- Immutable image and verifier inventory management become deployment responsibilities.
- The current binding registry and Target-I/O-zero Worker contract are necessary foundations but do not, by themselves, provide live specialist execution.
- AGENTIC-003D remains required before any Worker result can become a Finding, Graph edge, report, SARIF result, or PoC.

## Security considerations

- Serialized plans, bindings, receipts, approvals, Permits, and Worker statements are evidence, not restart or execution authority.
- Exact content digests, versions, activation, action, and deployment pins are required; matching names or IDs alone is not sufficient.
- Caller-authored route, payload, target, transport, egress policy, catalog, Worker image, backend, or verifier material must not cross into the live capsule.
- Grant consumption is single-use. If the generic Gateway represents the first call as call index zero, that value must be internally sealed to the already consumed exact one-call Grant and must not trigger a second ledger consumption or be caller-selectable.
- Aggregate Web source or validation Worker authority must not be reused for specialist target execution.
- Registry close, owner task completion, and deployment shutdown must abandon every pre-dispatch claim and persist its terminal reason.
- A post-dispatch timeout is not proof that no target action occurred. It must produce an outcome-unknown receipt and suppress automatic redispatch.
- Worker signatures prove only the statement bound to the pinned verification key. They do not replace current Campaign, Graph, catalog, approval, Permit, deployment, or backend checks.

## Migration

The change is additive. Existing v1 artifacts, readers, activations, plans, Grants, approvals, Permits, started executions, and audit bindings remain readable and inert.

Executable runs must be newly planned under the v2 contract. There is no conversion of an existing v1 plan or Permit into v2 authority, no automatic reissue, and no reconstruction of a live capsule from stored artifacts. Existing C3C Target-I/O-zero Worker statements remain valid only as conformance evidence.

Deployment migration for v2 must explicitly install the immutable Worker image digest, command, backend identity, verification key, and coordinator policy before any v2 activation is admitted. Mixed deployments must fail closed when those pins are absent or disagree.

## Rollback

Rollback disables v2 activation admission, the executable coordinator, and the backend bridge. It does not change v1 and does not require deleting the Target-I/O-zero conformance foundation.

Durable receipts, registry tombstones, abandoned claims, and outcome-unknown records must be preserved. Rollback must not rewrite them as unused authority, refund or reissue a Grant, reconstruct a capsule, or automatically retry a dispatch. Because the existing conformance Worker performs no target I/O, retaining its audit artifacts requires no target-side rollback.

## Rejected alternatives

- **Make v1 executable in place.** This would change a content-addressed inert contract without changing its approved identity.
- **Plan with v1 and substitute v2 after Permit issuance.** Tool-ID routing would conceal a capability and implementation identity change outside the approval chain.
- **Use the serialized binding as a bearer credential.** This would make audit evidence replayable and detach execution from the exact Store, task, database runtime, and deployment.
- **Reconstruct live authority after restart.** Durable evidence cannot prove continuity of process-local task and runtime ownership.
- **Treat the Target-I/O-zero statement as production Worker evidence.** Its contract explicitly denies backend and target I/O and all production promotion authority.
- **Release or retry a claim after timeout.** A timeout after backend dispatch cannot prove that the target action did not occur.
- **Fold independent validation and promotion into C3C.** This would collapse dispatch enforcement and 003D evidence adjudication into one trust domain.

## Related documents

- ADR-0314: Pin Specialist Permit Dispatch to One Deployment and Record Grant Consumption
- ADR-0313: Enter the Specialist Dispatch Crash Fence Inside the Approved Permit Callback
- ADR-0311: Define and Activate Exact Specialist Capabilities without Dispatch Authority
- AGENTIC-003 specialist dispatch contracts
