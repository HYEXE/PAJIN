# ADR-0138: Compose Batch Runtime Explicitly and Retain Unknown Journals

- Status: Accepted
- Date: 2026-08-09

## Context

ADR-0136 and ADR-0137 define a host-local coordinator over existing single-action approval,
ActionPermit, receipt, and cleanup authorities. They intentionally stop at a direct-call API. A
runtime connection must not silently turn every General Attack or Control Plane action into a
batch, inject another Permit store, accept unsealed completion, or discard an unknown journal after
an arbitrary age.

The coordinator journal is separate from the Graph database. A crash can therefore leave
`claim-started` or `dispatch-started-outcome-unknown` even when the Graph or Worker has advanced.
Backup and retention must preserve that ambiguity rather than manufacture non-execution.

## Decision

1. Keep every existing single-action entry point unchanged. General Attack gains a separate batch
   method and Control Plane gains a separate `capability-graph-batch-v1` Job profile.
2. General Attack rebuilds the current action and constructs the batch Graph authority from the
   gate's existing activation, verifier, Permit store, cleanup authority, clock, and TTL. External
   batch dispatch authority injection is not allowed.
3. Require exact item approval equality. For reversible-write, additionally require the exact
   current cleanup request and require terminal evidence to carry the existing restored-state
   assessment digest through the pinned completion authority.
4. Version the Control Plane batch deployment as v1alpha2. Pin the complete batch inventory,
   host-local journal path, and optional pending cancellations in the startup deployment digest.
5. Limit the Control Plane batch profile to current no-write approval policy. Keep write and T3+
   closed.
6. Seal the Capability Gateway Run after its terminal audit and before the journal accepts Worker
   completion. Reload the seal and exact Gateway outcome digest inside the deployment completion
   authority.
7. Create local journal backups only after every logical record re-verifies under the current
   deployment authorities. Bind database bytes and the complete logical-state digest in a canonical
   content-addressed manifest. Retain each consumed canonical authorization as immutable journal
   evidence so terminal completion can be re-verified; retained evidence never grants redispatch.
8. Restore only into a new path and require the caller to supply the batch input, completion, and
   cancellation authorities again. A backup never contains durable verifier-code identity.
9. Expose retention as a verified assessment, not a delete operation. Pending or manual-review
   state is never deletion-eligible. Terminal state becomes eligible only after the configured
   minimum deadline.
10. Keep cross-host fencing, remote signed/encrypted retention, verifier anti-rollback, journal and
    Graph atomicity, T3+, and Control Plane reversible writes out of scope.

## Consequences

- Runtime batch use is visible in both the deployment and Job profile.
- Existing single-action behavior and wire compatibility remain intact.
- Control Plane completion cannot become terminal before its Gateway evidence is sealed.
- General Attack reversible items retain their exact cleanup hold and cannot close without the
  deployment's restored-state evidence mapping.
- A copied journal can be restored locally without losing partial, cancelled, or unknown state.
- Operators receive deletion eligibility evidence, but PAJIN does not perform destructive
  retention cleanup.
- A local content digest does not authenticate an untrusted backup repository. That requires a
  later signed/encrypted anti-rollback layer.

## Rejected alternatives

### Enable batch behavior in the existing profiles

Rejected because a deployment or Job that previously represented one action would acquire new
coordination and persistence semantics without an explicit opt-in.

### Let runtime callers inject a batch Graph dispatcher

Rejected because a caller could select another Permit store, policy registry, or verifier while the
General Attack gate appeared to validate the original deployment.

### Finalize Control Plane completion before sealing the Run

Rejected because the completion authority would be authenticating mutable process state rather
than durable Gateway evidence.

### Delete journals after a fixed age

Rejected because age does not resolve pending claims or unknown outcomes. Deletion would erase the
only conservative non-redispatch evidence.

### Treat the journal backup as a Graph backup

Rejected because the journal coordinates but does not own approvals, Permits, receipts, or cleanup
reservations. Both stores must be retained and adjudicated according to their own authorities.

## Compatibility and rollback

Deployment v1alpha1, `capability-graph-v1`, General Attack `dispatch_once()`, Graph schema and backup
wires remain readable and unchanged. Removing the C3 runtime entry points does not revoke consumed
authority. Rollback must retain journals, backups, Graph records, and manual-review classifications.
