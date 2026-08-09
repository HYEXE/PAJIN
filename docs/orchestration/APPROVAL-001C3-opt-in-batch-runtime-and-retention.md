# APPROVAL-001C3: Opt-in Batch Runtime and Journal Retention

- Status: Locally implemented
- Date: 2026-08-09
- Prerequisites: APPROVAL-001A, APPROVAL-001B, APPROVAL-001C1, APPROVAL-001C2, ADR-0138

## Purpose

Connect the existing host-local batch coordinator to explicit General Attack and Control Plane
entry points without changing either single-action default. Add a verified local backup, new-path
restore, and retention assessment for the coordinator journal without creating deletion,
redispatch, or cross-host authority.

## General Attack opt-in entry point

`GeneralAttackActionPermitGate.dispatch_approved_batch_item_once()` is separate from
`dispatch_once()`. It rebuilds the complete PERMIT-002/003 predecessor chain, current activation,
Proposal, deployment-supplied approval, and optional reversible cleanup request before selecting
one batch ordinal. The item approval must equal the rebuilt approval exactly.

The gate constructs the existing no-write or approved-reversible Graph authority from its own
activation, verifier, Permit store, cleanup authority, clock, and TTL. A caller cannot inject an
alternate Graph dispatcher. No-write items must have no cleanup request. Reversible-write items
must carry the exact request returned by the current code-owned cleanup binder. Irreversible-write,
missing cleanup authority, approval-policy drift, cross-item substitution, and T3+ fail before
Graph consumption.

The async callback returns an `ActionApprovalBatchCompletion`. For reversible work, the callback
receives the exact `ActionCleanupReservation`; its deployment-pinned journal completion authority
must map the existing sealed `GeneralAttackCleanupAssessment.assessmentDigest` to
`restoredStateEvidenceDigest`. The gate does not reinterpret a source result as restored-state
evidence and does not release cleanup capacity.

## Control Plane opt-in profile

The existing deployment v1alpha1 and `capability-graph-v1` Job profile remain unchanged. Batch
execution requires deployment wire v1alpha2 with all of the following:

- an exact `actionApprovalBatches` inventory whose no-write items also exist in
  `actionApprovals`;
- a separate absolute `actionApprovalBatchJournal` path; and
- optional pre-pinned `actionApprovalBatchCancellations` for pending-only delivery.

Only `capability-graph-batch-v1` Jobs can select `batchId`, `batchDigest`, and `itemOrdinal`. The
selected approval, Proposal, Decision, release, prepared action, activation, and current policy
must agree. The coordinator consumes the existing approval and Permit, then the unchanged
Capability Gateway records its claimed/completed audit. The Run is sealed before journal terminal
completion is accepted. The deployment completion authority reloads that seal and requires its
exact Gateway outcome digest. Retry resolves the durable Permit and receipt but never invokes the
Gateway again.

Control Plane batch write support remains closed because the current deployment does not compose a
cleanup binder, CleanupPermit path, or restored-state verifier. Static cancellation delivery first
registers the exact pinned batch and can cancel only the pinned still-pending subset.

## Journal backup and retention

`SQLiteActionApprovalBatchJournal.create_backup()` copies one SQLite snapshot, reopens it with the
same deployment authorities, verifies every batch/item/event chain, and publishes a database plus
canonical content-addressed manifest. The manifest binds the schema, database bytes, complete
logical journal-state digest, minimum retention deadline, terminal count, manual-review flag, and
deletion eligibility.

`restore_backup()` accepts the database only when the manifest is canonical, byte length and
SHA-256 agree, the complete logical state re-verifies under caller-supplied deployment authorities,
and the destination did not previously exist. Pending, claim-started, outcome-unknown, terminal,
and cancelled states are restored without reinterpretation.

`assess_retention()` is evidence only. It reports deletion eligibility only when at least one batch
exists, every batch is terminal or fully cancelled, no item requires manual review, and the minimum
retention deadline has passed. The implementation never deletes a journal. Pending and unknown
states remain ineligible regardless of age.

The local manifest is integrity metadata, not an external signature or encrypted retention
object. Transport through an untrusted or remote repository requires a separately authenticated,
encrypted, anti-rollback format. A restored journal must still be paired with the authoritative
Graph database; it cannot restore consumed approvals, Permits, receipts, or cleanup reservations.

## Fail-closed boundaries

- deployment v1alpha1 carrying any batch control;
- batch approval absent from or reused across the deployment approval inventory;
- Control Plane write/cleanup item or unsupported policy shape;
- General Attack approval, cleanup request, activation, Proposal, or ordinal substitution;
- unsealed or mismatched Control Plane Gateway completion evidence;
- unpinned cancellation or cancellation of a claimed item;
- non-canonical, linked, replaced, tampered, schema-modified, or logically inconsistent backup;
- restore into an existing path; and
- any pending or manual-review-required journal retention deletion claim.

## Compatibility and rollback

All changes are additive. Existing Graph schema v4/v1alpha3 backup, approval, ActionPermit,
cleanup, Gateway, General Attack `dispatch_once()`, and Control Plane `capability-graph-v1` wires do
not change. Rollback removes the opt-in composition but retains the batch journal and Graph evidence
for audit. Unknown items cannot be deleted or converted into pending work.
