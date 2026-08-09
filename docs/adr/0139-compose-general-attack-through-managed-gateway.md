# ADR-0139: Compose General Attack Through the Managed Gateway

- Status: Accepted
- Date: 2026-08-09

## Context

PERMIT-003 exact-rebuilds General Attack authority and consumes the existing GRAPH ActionPermit,
but deliberately leaves its callback unconnected to a product Gateway. PERMIT-004A authenticates a
completed sealed Gateway lifecycle, but it deliberately does not select a Run path, Grant, Gateway,
or Worker. Tests have composed these pieces manually; no bounded product entry point owns their
intersection.

Adding another Permit, dispatch ledger, or Supervisor-specific Gateway would duplicate established
authority and weaken exact retry semantics. Accepting a caller-selected Run or Grant would allow a
self-consistent alternate audit to stand in for deployment state. Enabling write or T2 execution at
the same time would exceed the current production Capability and cleanup boundary.

## Decision

1. Add one explicit `GeneralAttackActionExecutionGate` for T0/T1 `none` and `read-only` actions.
2. Reuse `GeneralAttackActionPermitGate`, the GRAPH Permit store, `ToolGateway`,
   `ExistingModeCapabilityGatewayDispatcher`, `RunStore`, and `GeneralAttackActionOutcomeGate`
   unchanged.
3. Require a deployment ID, absolute managed Run root, verified activation, Tool registry, Policy
   engine, Worker backend, Permit input authority, and a separate execution input authority.
4. Let the execution authority resolve the exact Envelope, Decision, Grant, and used-call count
   before Permit consumption. Exact-match the existing Permit input authority's Envelope and
   Decision against those values before claim. Derive the Run path from the managed root instead of
   accepting it.
5. Seal and verify one deployment-bound Run anchor as the first event before the Permit claim.
6. Adapt only the already-consumed exact Permit into the existing Gateway dispatcher. The adapter
   cannot mint, replace, or reconsume a Permit.
7. Seal terminal Gateway audit before invoking the existing outcome gate. Bind its internal input
   resolver to the same Run anchor and Grant used for dispatch.
8. Reuse APPROVAL-001A only for T0/T1 Definitions that already require approval. Reject T2, T3+,
   write, and cleanup-required inputs before Worker dispatch.
9. Treat callback failure, cancellation, missing terminal audit, and exact non-dispatched retry as
   terminal no-redispatch states.

## Consequences

- General Attack gains a concrete opt-in execution boundary without gaining new execution
  authority or changing a wire format.
- The deployment, Permit input, and execution input providers remain explicit process-local TCBs.
- Managed Run selection and pre-claim anchor creation are code-owned by the composition rather than
  supplied by action output.
- First execution yields both the existing durable Permit evidence and the existing authenticated
  outcome assessment. Exact retry never calls the Worker twice.
- T2 and reversible-write product activation remain separate follow-up decisions.

## Rejected alternatives

### Add a Supervisor Permit or execution ledger

Rejected because GRAPH already owns atomic Permit consumption and RunStore already owns Gateway
audit. Another ledger would create split-brain retry and recovery rules.

### Let the callback choose a Run, Grant, or Gateway

Rejected because caller-selected operational authority can produce a self-consistent alternate
execution and audit path.

### Expose T2 or reversible-write in the first composition

Rejected because T2 requires an explicit product approval policy and reversible write requires a
production cleanup Capability, Grant, mapping, restored-state verifier, and hold-recovery process.

## Compatibility and rollback

The change is additive. Existing Permit, approval, Graph, Gateway, Worker, Run, and outcome wires
remain unchanged. Rollback removes the new caller while retaining consumed authority and sealed
audit evidence. No database migration or downgrade path is introduced.

## Related documents

- [SUP-007A contract](../orchestration/SUP-007A-opt-in-general-attack-execution.md)
- [PERMIT-003 contract](../orchestration/PERMIT-003-exact-single-use-action-permit.md)
- [PERMIT-004A contract](../orchestration/PERMIT-004A-authenticated-action-outcome-gate.md)
- [ADR-0130](0130-reuse-graph-permit-at-the-general-attack-boundary.md)
