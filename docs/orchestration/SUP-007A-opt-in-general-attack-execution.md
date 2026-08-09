# SUP-007A: Opt-in General Attack Execution

## Purpose

Compose the existing General Attack intent, ActionPermit, Capability Gateway, managed Run audit,
and authenticated outcome gates into one explicit product entry point for T0/T1 no-write actions.
The composition does not introduce another Permit, execution store, Grant type, or result authority.

## Scope

`GeneralAttackActionExecutionGate.execute_once()` is an additive direct-call opt-in. It admits only
actions whose source proposal is T0 or T1, whose side-effect class is `none` or `read-only`, and
whose cleanup metadata is false. A T0/T1 Definition that requires operator approval can use the
existing APPROVAL-001A provider, verifier, issuer binding, receipt, and atomic Permit transaction.

T2 and T3+ actions, reversible or irreversible writes, cleanup-required actions, batch execution,
and automatic redispatch remain outside this slice. The existing single-action, batch, Common
Engine, Control Plane, and legacy execution entry points are unchanged.

## Authority intersection

Before any Permit claim, the gate requires all of the following:

1. a code-selected deployment ID and absolute managed Run root;
2. the existing verified `ExistingModeCapabilityActivation` and GRAPH Permit store;
3. the existing `GeneralAttackActionPermitInputAuthority` for Envelope, Decision, and price;
4. a separate `GeneralAttackActionExecutionInputAuthority` that resolves the exact Envelope,
   Decision, current `CapabilityGrant`, and already-used call count for this source intent;
5. deployment-selected Tool registry, Policy engine, Worker backend, optional Secret broker, and
   rate-limit ledger;
6. when the Definition requires approval, the existing APPROVAL-001A authority, verifier, and
   exact issuer binding.

The gate canonicalizes the execution inputs, derives the Run path from the managed root, Campaign,
and generated Envelope Run ID, rejects link boundaries, writes exactly one
`CapabilityGraphRunAuditAnchor`, seals it before the Permit claim, and verifies that it is the first
Run event. The anchor binds the deployment, Campaign, Envelope, release set, activation set, and
compiler identity. A per-call Permit input adapter then requires the existing Permit authority to
return the same exact Envelope and Decision before GRAPH can consume a Permit.

## Dispatch and outcome

The gate invokes the existing `GeneralAttackActionPermitGate`. Its first-consumption callback
receives the consumed Permit, current prepared action, and exact Graph proposal. The composition
then:

1. rechecks that the consumed Permit and proposal still match the pre-resolved Envelope and
   Decision;
2. creates the existing `ToolGateway` over the deployment-owned Tool registry, Worker, and exact
   managed Run store;
3. uses `ExistingModeCapabilityGatewayDispatcher` with a non-authoritative adapter that can return
   only the already-consumed exact Permit;
4. seals the Run after success, failure, or cancellation;
5. passes the first successful `GatewayOutcome` to `GeneralAttackActionOutcomeGate` with an
   internal exact Run-anchor-and-Grant resolver.

The returned `GeneralAttackActionExecutionResult` contains the existing Permit result and
authenticated outcome assessment. It is a projection of those authorities and grants no replay,
cleanup, approval, Scope, Capability, or additional execution authority.

## Failure and retry semantics

- Failure before Permit claim creates no Worker dispatch authority.
- Failure or cancellation after Permit consumption remains terminal under GRAPH at-most-once
  semantics. The gate attempts to seal the resulting audit and does not retry.
- An exact retry can recover the durable Permit tuple through the existing Permit gate but the
  product composition rejects the non-dispatched result. It never calls the Worker again and does
  not reconstruct success from absence or mutable caller data.
- A missing, duplicate, unsealed, substituted, or non-first Run anchor fails closed before Worker
  dispatch.
- A mismatched Grant, Envelope, Decision, prepared Capability, proposal, Run, or audit record fails
  closed. A Gateway or Oracle success without the sealed exact audit is not accepted.

## Negative boundaries

Tests must cover at least:

- one successful T0/T1 no-write execution with a sealed pre-claim anchor and authenticated outcome;
- exact retry without a second Worker invocation;
- T2, T3+, write, and cleanup-required rejection before Worker dispatch;
- cross-Run, cross-Decision, cross-Grant, and activation substitution;
- linked or tampered Run state and missing terminal evidence;
- approval-required T0/T1 rejection without existing APPROVAL-001A authority.

## Compatibility and rollback

All existing public wire identities, Graph schemas, Run events, ActionPermit and approval records,
Gateway jobs, and outcome assessments remain unchanged. Rollback removes only the new opt-in
composition and retains every consumed Permit, approval receipt, Run event, seal, and result
assessment as immutable audit evidence.

## Remaining boundary

SUP-007B must decide whether and where to expose the composition through a concrete CLI, API, or
Control Plane deployment profile and must require a pre-approved Envelope for T2 while preserving
the T3+ default deny. Reversible-write product activation still requires a production Capability,
cleanup Grant and mapping, restored-state verifier, and operational hold-recovery contract.

## Related documents

- [PERMIT-003 contract](PERMIT-003-exact-single-use-action-permit.md)
- [PERMIT-004A contract](PERMIT-004A-authenticated-action-outcome-gate.md)
- [APPROVAL-001A contract](APPROVAL-001A-single-action-approval.md)
- [ADR-0139](../adr/0139-compose-general-attack-through-managed-gateway.md)
