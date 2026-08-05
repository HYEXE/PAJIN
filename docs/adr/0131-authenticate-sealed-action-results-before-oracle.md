# ADR-0131: Authenticate Sealed Action Results Before Oracle and Cleanup

- Status: Accepted
- Date: 2026-08-05

## Context

PERMIT-003 returns a generic in-process callback observation after consuming the existing GRAPH
ActionPermit. That observation, a raw `GatewayOutcome`, and its nested Tool and Worker results are
mutable values without independent producer or Run authority. The existing CAP-005 dispatcher
already records a Permit-bound claimed/terminal lifecycle and exact Gateway outcome digest, while
RunStore already seals the evidence artifact and provenance. CAP-002 already owns one Result
Normalizer, Success Oracle, Cleanup Handler, and Executor Adapter per activated Capability.

Invoking the Oracle or Cleanup Handler from the live callback value alone would allow missing,
uncertain, forged, or cross-action data to become semantic success or cleanup authority. Calling
the Executor Adapter again during assessment would prepare another Worker job unrelated to the
one that actually ran. Reusing the consumed ActionPermit for cleanup would also collapse two
different actions and bypass separate cleanup budgeting and single-use semantics.

The current activated inventory contains only `none` and `read-only` Capabilities with
`cleanupRequired=false`; no general cleanup request, Permit, store transaction, dispatcher, or
write-capable positive path exists yet.

## Decision

Add a direct-call `GeneralAttackActionOutcomeGate` and additive content-addressed
`GeneralAttackActionOutcomeAssessment` with these rules:

1. Exact-rebuild PERMIT-001/002 and current signed activation/preparation, then require the current
   GRAPH store to contain the exact consumed PERMIT-003 Permit and proposal lineage.
2. Do not accept a caller-selected Run path. Require a deployment input authority to resolve the
   authoritative Run, exact `CapabilityGraphRunAuditAnchor` with a seal covering it before claim,
   and actual Gateway Grant.
   Intersect the anchor with current Campaign, Envelope, release-set, activation-set, and compiler
   authority before interpreting the Run.
3. Load the exact Gateway evidence artifact from that resolved Run inside the gate. Reuse the
   existing verified Run loader, CAP-005 dispatch reconciliation, terminal audit event, and Gateway
   outcome digest rather than creating another result store or receipt authority.
4. Admit only a sealed completed lifecycle. Missing, exact-retry, consumed-without-claim,
   claimed-outcome-unknown, failed, cancelled, and expired states do not invoke outcome roles and
   never authorize redispatch.
5. Reconstruct request, policy decision, pre-evidence Tool result, safe Worker job metadata,
   Worker result, optional secret-lease metadata, artifact hash/provenance, and execution identity
   from the sealed evidence. Require one exact `worker.dispatched` audit and cross-check the full
   job plus lease IDs, bindings, fingerprints, TTLs, audience, Run scope, use, and revocation state.
   Require the live outcome, exact trusted Grant digest, and terminal audit to agree exactly.
6. Invoke the current activated Result Normalizer only after that authentication and require exact
   equality with the sealed pre-evidence result. Then invoke the current Success Oracle and record
   its bounded decision.
7. Bind the Executor Adapter authority identity but never call `prepare()` during result
   assessment. Actual execution authority is the completed sealed Gateway lifecycle.
8. Record a conservative data-flow observation from dispatch-audit-bound job metadata.
   `network=none` forbids observed egress;
   `egress-proxy` requires both current Definition permission and a host-trusted proxy log. Do not
   claim semantic information-flow or exfiltration attestation.
9. Support only `none` and `read-only` with `cleanupRequired=false`. Invoke the current Cleanup
   Handler and require `None`. Fix write admission, cleanup plan creation, cleanup Permit issuance,
   and cleanup execution authority to false.
10. Treat the assessment model as a non-authoritative output projection until
    `verify_assessment()` exact-rebuilds it from every predecessor and the deployment input
    authority.
11. Reject every write or cleanup-required Definition until a separate typed cleanup request,
   domain-separated bounded one-shot Permit, and aggregate Campaign budget transaction exist.
12. Keep Gateway/Worker product wiring in SUP-007 and add no default workflow, store, dispatcher,
    or database schema in this slice.

## Consequences

- CAP-002 Oracle and Cleanup Handler code can no longer be reached from an unauthenticated live
  result through this gate.
- Outcome assessment is bound to the same deployment Run anchor, Permit, activation, release,
  exact Grant digest, dispatch-audit Worker job, execution, sealed evidence, and current role
  identities that produced the existing audit.
- A self-consistent model instance or caller-selected self-sealed Run is not authenticated result
  authority; consumers must use the exact-rebuild verifier and deployment resolver.
- The deployment resolver and its canonical managed Run mapping are explicit TCB. This slice
  detects divergence inside the selected Run but does not authenticate a compromised provider's
  path selection against a second externally persisted locator.
- Assessment reverification re-evaluates the authenticated Oracle and Cleanup Handler before exact
  candidate equality; these roles are planning/evaluation authorities and must not perform cleanup
  execution or external side effects.
- The Executor binding is explicit without manufacturing a second Worker job.
- Side-effect class remains a Definition ceiling, not proof of external absence. Data-flow remains
  a bounded transport observation, not a semantic information-flow attestation.
- Current no-write Capabilities gain an authenticated result projection. Write and cleanup-required
  Capabilities remain unavailable rather than receiving a placeholder cleanup authority.
- A later cleanup slice must share the existing GRAPH durability and budget domain; it cannot use
  a disconnected ledger or reinterpret the original action Permit.

## Rejected alternatives

### Trust the live PERMIT-003 callback result

Rejected because the generic dispatch result is explicitly non-authoritative and does not prove a
terminal audit, sealed evidence, Worker execution, or current Capability authority.

### Treat `ToolResult.success` as semantic success

Rejected because Tool success is transport-level output. The registered Success Oracle must
recompute Capability-specific meaning from the exact authenticated normalized result.

### Call the Executor Adapter during assessment

Rejected because it would prepare a new Worker job rather than authenticate the job that actually
ran. PERMIT-004A binds only the adapter identity and uses sealed Gateway evidence as execution
authority.

### Add a new outcome store or receipt ledger

Rejected because CAP-005 audit and RunStore already own Permit-bound lifecycle, artifact hash,
provenance, and sealing. A second result authority would be redundant and could diverge.

### Reuse the consumed ActionPermit for cleanup

Rejected because cleanup has different lineage, target, Capability, budget, and at-most-once
semantics. The action Permit is immutable evidence of an already consumed dispatch, not a bearer
token for compensation.

### Add a fixture-only write Capability and placeholder cleanup Permit now

Rejected because no production write Capability exists and a disconnected fixture ledger would
either bypass aggregate Campaign budget or duplicate GRAPH authority. The write path stays closed
until its full smallest vertical slice is implemented.

## Compatibility and rollback

All additions are direct-call and additive. Existing public readers, wire formats, stores,
databases, Gateway and Worker behavior, and default workflows remain unchanged. Rollback removes
the new assessment gate and consumers; consumed Permits and sealed Run evidence remain historical
and non-retriable.

## Related documents

- [PERMIT-004A contract](../orchestration/PERMIT-004A-authenticated-action-outcome-gate.md)
- [PERMIT-003 contract](../orchestration/PERMIT-003-exact-single-use-action-permit.md)
- [CAP-002 contract](../capability/CAP-002-metadata-code-backed-authority-interfaces.md)
- [CAP-005 contract](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
