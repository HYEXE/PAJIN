# ADR-0133: Authenticate and Verify Reversible Cleanup

- Status: Accepted
- Date: 2026-08-05

## Context

ADR-0131 authenticates completed no-write results before semantic policy, while ADR-0132 reserves
cleanup capacity before a reversible write and supplies a separate one-shot CleanupPermit. The B1
GRAPH request deliberately treats its outcome and Handler-plan fields as external input-authority
coordinates. Treating a self-consistent CleanupRequest as proof would allow a caller to invent a
write result, select a cleanup Capability, or claim restoration from Gateway success alone.

Appending cleanup audit to the same managed Run introduces another identity hazard: the latest Run
root changes after every cleanup event. A source outcome bound to that mutable root would change
during its own compensation and could not be re-authenticated after sealing cleanup evidence.

## Decision

1. Extract the PERMIT-004A sealed-result verification into a private authentication core that
   invokes neither Success Oracle nor Cleanup Handler. Preserve the existing public no-write
   assessment wire and behavior.
2. Admit a cleanup source only from a completed authenticated `reversible-write +
   cleanupRequired=true` execution with its exact pre-action B1 hold.
3. Bind source cleanup identity to the immutable source-evidence seal root rather than the mutable
   latest Run root. Re-authenticate the source at each claim and assessment boundary.
4. Invoke the current source Cleanup Handler after authentication and regardless of the source
   Success Oracle decision. Accept one strict `restore-target` plan with bounded parameters and an
   expected restored-state digest.
5. Resolve source-to-cleanup selection through a code-owned, content-addressed mapping to one
   distinct current activated release. Persist no parallel mapping store.
6. Require the current source Handler, current cleanup Executor, full prepared cleanup action,
   target, request units, and plan digest to equal the pre-action hold and B1 CleanupRequest. Rerun
   the Handler and exact-match its typed plan before and after CleanupPermit claim.
7. Require a fresh, single-call, non-delegable, exact-tool-and-target Grant issued after the source
   terminal event and bounded by CleanupPermit and Envelope expiry.
8. Fix the deployment Gateway, managed Run audit store, and restored-state verifier at gate
   construction. Require the audit path and Run ID to equal the authenticated source Run. Reuse
   `GraphCleanupPermitAuthority`, the unchanged Tool Gateway and Worker, but emit a separate cleanup
   dispatch audit and reconciliation domain. Exact retry and every uncertain terminal state grant
   no second execution.
9. Accept cleanup completion only when its Permit exact-matches the consumed GRAPH store record and
   one sealed completed cleanup lifecycle from the authenticated managed Run has exact Gateway,
   Worker, evidence, Normalizer, Oracle, release, mapping, and current role identities.
10. Require a separately code-identified verifier to observe the actual current target-state
    digest. Gateway or Oracle success without this equality does not prove restoration.
11. Keep all APIs additive and leave default Supervisor execution and production Capability
    activation out of scope.

## Consequences

- Compensation cannot be planned from caller-selected or merely self-consistent outcome material.
- Cleanup remains mandatory after an authenticated reversible execution even when the source
  semantic Oracle would report failure.
- Source identity remains stable while cleanup audit is appended to the same Run.
- The original ActionPermit never becomes a second bearer authority; a fresh Grant and distinct
  CleanupPermit are required.
- Failure, cancellation, expiry, crashes, and unknown cleanup outcomes consume authority without
  automatic retry.
- A successful cleanup Tool result is necessary but insufficient; actual restored state must be
  independently observed.
- The trusted computing base now explicitly includes deployment mapping, pricing, Run/Grant,
  cleanup Grant, and state-verifier authorities. Production composition must register and operate
  those authorities; the current inventory remains no-write.

## Rejected alternatives

### Reuse the original ActionPermit

Rejected because historical write lineage does not authorize a fresh cleanup request, Capability,
Grant, budget coordinate, or second Worker execution.

### Trust the CleanupRequest digest

Rejected because content addressing proves internal consistency, not managed-Run provenance,
current Handler output, signed release currency, or restored target state.

### Bind the source to the latest Run root

Rejected because cleanup events change that root and would make the authenticated source identity
self-invalidating. The earliest seal covering exact source evidence is immutable for this purpose.

### Treat Gateway or Oracle success as restoration

Rejected because a Tool may return success without restoring the target, or its output may describe
a stale or different state. A distinct state observer must read the current target.

### Add another cleanup database or execution path

Rejected because B1 already owns durable one-shot authority and the Tool Gateway already owns
policy and Worker dispatch. Another path would duplicate trust and retry semantics.

### Retry failed or unknown cleanup automatically

Rejected because an unobserved side effect may already have happened. Re-execution requires a
future explicit recovery authority, not inference from missing audit.

## Compatibility and rollback

PERMIT-004A public assessment, ActionProposal, ActionPermit, CleanupRequest, CleanupPermit, Tool
Gateway, Worker, and Graph schema-v3 wires remain unchanged. B2 adds new orchestration, mapping,
cleanup audit/reconciliation, plan, and assessment types. Existing no-write call sites keep their
behavior.

Rollback removes only the B2 caller. Existing holds, consumed Permits, and Run audit remain
immutable and cannot be retried or reinterpreted. Operators must retain B1 schema-v3 recovery
support and manually adjudicate unknown cleanup outcomes.

## Related documents

- [PERMIT-004B2 contract](../orchestration/PERMIT-004B2-authenticated-reversible-cleanup-dispatch.md)
- [ADR-0132](0132-pre-reserve-cleanup-capacity-before-reversible-write.md)
- [ADR-0131](0131-authenticate-sealed-action-results-before-oracle.md)
