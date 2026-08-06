# ADR-0134: Consume One Operator Approval with One ActionPermit

- Status: Accepted
- Date: 2026-08-05

## Context

GRAPH-006 already owns the final Snapshot, budget, and one-shot dispatch transaction. PERMIT-004B1
owns reversible cleanup capacity. Capability definitions already declare risk and
`approvalRequired`, but neither a caller boolean nor a model draft can authenticate operator
consent. Adding a parallel approval database or issuing a bearer approval token would split the
final execution decision and create retry, substitution, and partial-claim races.

The full APPROVAL-001 milestone also names batch and asynchronous work. Combining those semantics
with the first T2 path would require partial-claim and unknown-outcome policy before the smallest
single-action authority is proven.

## Decision

1. Add a content-addressed `ActionApprovalEnvelope` for one exact action only. Bind the complete
   Campaign, Run, MissionEnvelope, source intent, activation, release, Decision, Proposal, request,
   target, risk, reservation, expected Permit, issuer, principals, and time window.
2. Treat content addressing as integrity only. Require a deployment-pinned input authority to
   authenticate the issuer and complete approval immediately before and after the store boundary.
3. Reuse the existing GRAPH SQLite transaction. Persist approval, unchanged ActionPermit, and a
   non-reusable receipt atomically; exact retry returns the same durable tuple and no dispatch
   authority.
4. Pin a canonical full-activation approval policy registry at writer claim. Use distinct
   non-transferable writers for plain, approved, reversible, and cleanup transactions so a generic
   store caller cannot present self-selected policy or verifier objects.
5. Limit this slice to no-write T2 and T0/T1 definitions that explicitly require approval. Keep
   T2 write closed until approval and cleanup capacity can be consumed together. Reject T3+,
   batch, and async.
6. Bind the durable receipt into General Attack outcome assessment and Control Plane completion
   output. Preserve old no-approval assessment digests.
7. Advance the Graph database and current direct/retained backup formats to schema v4/v1alpha3,
   retaining strict verified reads for schema v3/v1alpha2 and schema v2/v1alpha1 without
   fabricating authority.
8. State that registry, writer, and verifier pins are process-local deployment TCB. Persistence of
   approval, Permit, and receipt does not imply durable cross-process verifier pinning.

## Consequences

- T2 no-write execution cannot begin from model output, caller intent, or content-addressing alone.
- Approval consumption and Permit consumption have one serial order and cannot partially commit.
- Exact retry and uncertain outcome preserve at-most-once dispatch.
- Existing ActionPermit, Gateway, Worker, and discovery wire identities remain unchanged.
- Direct Python composition must provide a full policy inventory and the correct path-specific
  authority; this intentionally rejects former self-selected policy call patterns.
- A trusted deployment must re-inject the same verifier and policy inventory after restart. An
  attacker who can choose runtime verifier code is outside this slice's TCB and remains a recorded
  deployment limitation.
- Batch, async, and T2 write semantics remain explicit follow-up rather than hidden generalization.

## Rejected alternatives

### Treat approval as another Capability Grant

Rejected because a Grant limits Tool access but does not bind the exact Decision, Proposal,
request, reservation, expected Permit, approver, or one-time approval consumption.

### Trust the approval digest as issuer proof

Rejected because anyone can create internally consistent bytes. Issuer authentication requires a
deployment-owned authority.

### Store approval separately from Permit

Rejected because a crash could consume only one side, permitting partial authority, ambiguous
retry, or approval reuse.

### Let each call supply its policy and verifier

Rejected because generic callers could construct permissive policy or self-verifying authorities.
Deployment claims the complete registry and verifier before request material is considered.

### Implement batch and async in the same wire

Rejected because single-action exact retry does not define partial batch claim, cancellation,
lease transfer, or outcome-unknown reconciliation. Those require separately bounded contracts.

### Persist a verifier identity without a deployment trust design

Rejected because a string or digest in SQLite cannot by itself prove that reopened runtime code is
the same trusted verifier. Cross-process pinning requires a separate signed deployment or host
attestation authority.

## Compatibility and rollback

All new public models and Job fields are additive. Existing no-approval actions retain their wire
and assessment digest. Schema v4 is forward-only in place; rollback must retain v4 readers and
must not delete or reinterpret consumed approvals, Permits, or receipts.

## Related documents

- [APPROVAL-001A contract](../orchestration/APPROVAL-001A-single-action-approval.md)
- [GRAPH-006 contract](../graph/GRAPH-006-atomic-action-permit-authority.md)
- [ADR-0133](0133-authenticate-and-verify-reversible-cleanup.md)
- [ADR-0132](0132-pre-reserve-cleanup-capacity-before-reversible-write.md)
