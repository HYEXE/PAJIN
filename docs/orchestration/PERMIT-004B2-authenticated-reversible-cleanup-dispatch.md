# PERMIT-004B2: Authenticated Reversible-write Cleanup Dispatch

- Status: Implemented
- Runtime APIs: `pajin.supervision.GeneralAttackActionCleanupGate`,
  `pajin.capabilities.ExistingModeCleanupCapabilityGatewayDispatcher`
- Record APIs: `pajin.dev/general-attack-cleanup-plan/v1alpha1`,
  `pajin.dev/cleanup-capability-dispatch-audit-event/v1alpha1`,
  `pajin.dev/cleanup-capability-dispatch-reconciliation/v1alpha1`, and
  `pajin.dev/general-attack-cleanup-assessment/v1alpha1`
- Decision: [ADR-0133](../adr/0133-authenticate-and-verify-reversible-cleanup.md)

## Scope

PERMIT-004B2 connects the PERMIT-004B1 durable cleanup reservation and one-shot Permit to one
authenticated general-attack reversible-write result. It reuses the PERMIT-004A sealed-result
authentication core, invokes the current source Cleanup Handler only after authentication, maps the
source Capability to one distinct current cleanup Capability through code-owned authority, and
dispatches the resulting request through the existing Tool Gateway and Worker.

The final assessment requires two independent facts: a sealed completed cleanup Gateway lifecycle
whose current Success Oracle reports success, and a code-identified verifier observation of the
actual restored target state. Gateway success alone is never restored-state authority.

This contract does not activate a default Supervisor workflow or add a production reversible-write
Capability. The current CAP-005 inventory remains no-write. The executable positive path is an
isolated synthetic state write and restoration fixture.

## Pre-action eligibility and hold

`GeneralAttackActionPermitGate` keeps its existing no-write behavior. A write can enter the action
callback only when all of the following are true:

- its current signed Definition is exactly `reversible-write` with `cleanupRequired=true`;
- a `GeneralAttackReversibleCleanupAuthority` is explicitly supplied;
- a code-owned mapping resolves a distinct cleanup Capability in the same current activation;
- current source Cleanup Handler and cleanup Executor identities match the reservation request;
- trusted fixed-point price and claim deadline fit the existing Envelope; and
- PERMIT-004B1 atomically commits the ActionPermit and exact cleanup capacity hold.

Irreversible writes, cleanup-not-required writes, absent mapping or input authority, stale release,
role drift, recursive cleanup, and a cleanup Capability equal to the source Capability fail before
the Worker callback.

## Authenticated source and stable identity

The private PERMIT-004A authentication core exact-rebuilds the source intent, Graph proposal,
stored consumed ActionPermit, deployment-owned Run and anchor, Grant, completed dispatch audit,
Gateway outcome, Worker job and result, normalized evidence bytes, artifact provenance, and all
current CAP-002 authority bindings. It invokes neither the Success Oracle nor Cleanup Handler.

The cleanup source identity binds that authenticated material in a separate domain. Its Run
coordinate is the earliest seal root that covers the source evidence, not the mutable latest Run
root. Consequently, appending and sealing cleanup audit events in the same Run cannot change the
source outcome identity. The source identity is re-authenticated before CleanupPermit claim and
again before restored-state assessment.

Semantic source success is deliberately not a precondition for compensation. Once a reversible
write has a completed authenticated execution, the current Cleanup Handler is consulted regardless
of the source Success Oracle decision.

## Typed plan and cleanup Capability

The current source Cleanup Handler must return exactly one bounded
`GeneralAttackCleanupPlan`. Revision one admits only the literal `restore-target` operation, strict
JSON parameters, and one expected restored-state SHA-256 digest. `None`, an alternate operation,
extra fields, oversized material, or recursive cleanup fails closed.

`CleanupCapabilityMappingRegistry` is code-owned and persisted nowhere. Its content-addressed
binding includes adapter implementation and stable context, exact source Capability, distinct
current cleanup activation/release, and one bounded HTTP method. Duplicate, missing, historical,
ambiguous, identity-drifting, or activation-drifting mappings are rejected.

The cleanup plan digest binds the typed plan, mapping digest, current source Handler, current
cleanup Executor, and complete prepared cleanup action. The generated `CleanupRequest` must match
the pre-action hold's target, Capability, Handler, Executor, request units, and exact source
lineage. The B1 input authority reruns and strict-parses the current Handler plan before and after
the durable claim; same-identity plan equivocation fails before Worker dispatch.

## Fresh Grant and one-shot dispatch

A deployment-owned `GeneralAttackCleanupGrantInputAuthority` supplies a fresh Grant. The gate
requires a different Grant ID and digest from the source Grant, the exact cleanup agent, tool and
target, one call, no delegation, no higher risk, issuance strictly after the source terminal event,
and expiry no later than both CleanupPermit and Envelope. The gate computes the prospective Permit
window and rejects a deterministically overlong or not-yet-active Grant before consuming the
one-shot Permit; the dispatcher repeats the check at callback time.

`GraphCleanupPermitAuthority` re-authenticates the sealed source and current plan before and after
its durable claim. The deployment Tool Gateway and audit store are fixed when the cleanup gate is
constructed; the audit store's exact resolved path and Run ID must equal the authenticated managed
Run before Handler or Permit claim. `ExistingModeCleanupCapabilityGatewayDispatcher` then consumes
only that domain-separated CleanupPermit and calls the unchanged Tool Gateway. The original
ActionPermit is lineage only. Exact retries return the consumed CleanupPermit without invoking
Gateway or Worker again.

Cleanup dispatch emits a separate claimed/terminal audit lifecycle. Reconciliation classifies
completed, failed, cancelled, expired, consumed-without-claim, and claimed-outcome-unknown states.
Only one sealed `claimed -> completed` lifecycle can reach restored-state verification. A failure,
cancel, expiry, crash before audit, or crash after an uncertain Gateway side effect is terminal and
never grants automatic redispatch.

## Restored-state assessment

`verify_restored` re-authenticates the source and exact cleanup lineage, requires the canonical
CleanupPermit to equal the actually stored consumed GRAPH record, validates the fresh Grant, loads
the cleanup evidence artifact only from the source authentication authority's managed Run, and
exact-matches the reconciliation, terminal event, Gateway outcome, Worker dispatch, normalized Tool
result, mapping, release, and current cleanup roles. The cleanup Success Oracle must report
`succeeded`, while its Cleanup Handler must return `None` to prevent recursive compensation.

A deployment-owned code-identified `GeneralAttackCleanupRestoredStateVerifier` is fixed when the
gate is constructed and then independently observes the current target. Callers cannot substitute
a verifier at assessment time. Its implementation type, stable context, ID, version, and digest are
bound in the assessment. The observed SHA-256 must equal the Handler plan's expected state digest.
The assessment is content-addressed, sets original-ActionPermit reuse and redispatch authority to
false, and is not itself execution authority.

## Fail-closed conditions

- incomplete, failed, uncertain, forged, cross-action, or mutated source evidence;
- irreversible or cleanup-ineligible source Definition;
- absent, duplicate, same-Capability, stale, or identity-drifting cleanup mapping;
- missing, malformed, multiple, recursive, or substituted Handler plan;
- pre-action hold, Target, Handler, Executor, price, ToolRequest, release, Decision, Snapshot, or
  CleanupPermit substitution;
- alternate same-Run-ID audit/evidence store, caller-selected Run path, assessment-time verifier
  substitution, or a canonical but never-issued CleanupPermit;
- reused, stale, not-yet-active, expired, overbroad, delegated, or cross-Campaign cleanup Grant;
- cleanup failure, cancellation, expiry, consumed-without-claim, claimed-outcome-unknown, or
  attempted automatic retry;
- cleanup audit, evidence, Worker job/result, Normalizer, Oracle, or authority-role drift; and
- Gateway success without an exact independent restored-state observation.

## Compatibility and rollback

The ActionProposal, ActionPermit, PERMIT-004A assessment, Tool Gateway, Worker, and B1 GRAPH wire
formats remain unchanged. New source and cleanup orchestration APIs are additive. B2 writes only
domain-separated cleanup audit and reconciliation events into the existing Run and uses the
existing schema-v3 Graph store.

Rolling back the B2 caller leaves any consumed ActionPermit, cleanup reservation, CleanupPermit,
and Run audit as immutable history. It must not reinterpret an original ActionPermit as cleanup
authority or retry an unknown cleanup outcome. Schema-v3 recovery requirements remain governed by
PERMIT-004B1.

## Verification

Tests cover isolated write-to-restore execution, a distinct signed cleanup release, pre-action
capacity hold, fresh least-authority Grant, existing Gateway/Worker use, stable source identity
after cleanup events, exact retry without a second Worker call, sealed cleanup reconciliation,
independent actual-state verification, irreversible and unreserved write rejection, Handler plan
equivocation and malformed plan rejection, canonical never-issued CleanupPermit/plan lineage,
alternate same-Run-ID audit store, false restored-state observation, stale/overbroad/overlong Grant,
request and release drift, cross-request audit, failure, cancellation, expiry, and both crash
uncertainty classes.

## Remaining boundary

Production composition still requires deployment-owned Envelope, Decision/provenance, pricing,
Run/Grant, cleanup Grant, mapping, and restored-state verifier authorities. No current CAP-005
release is reversible-write. SUP-007A opens only the no-write direct-call path; SUP-007B or a later
explicit write profile remains responsible for any reversible-write product activation.
Expired or abandoned pre-action holds still require a separate operational recovery/release
contract; B2 does not manufacture restored state or reusable budget.

## Related documents

- [PERMIT-004B1 contract](PERMIT-004B1-pre-reserved-one-shot-cleanup-permit.md)
- [PERMIT-004A contract](PERMIT-004A-authenticated-action-outcome-gate.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
