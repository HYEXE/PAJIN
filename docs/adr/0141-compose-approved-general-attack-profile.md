# ADR-0141: Compose the Approved General Attack Profile

- Status: Accepted
- Date: 2026-08-09

## Context

APPROVAL-001A already atomically consumes one deployment-authenticated no-write approval with the
existing GRAPH Permit and durable non-reusable receipt. General Attack already knows how to rebuild
the exact action, bind this approval, and authenticate the receipt in its outcome. SUP-007B exposes
only approval-free T0/T1 actions because its Control Plane composition does not provide those
approval inputs.

The Capability Graph Worker deployment already pins the approval inventory and constructs the
verifier used by `capability-graph-v1`. Duplicating that verifier, accepting an approval digest as
issuer proof, or adding a second approval store would split the existing authority.

## Decision

1. Add a separate `general-attack-approved-v1` Campaign Job profile. Do not widen
   `general-attack-v1`.
2. Include one complete `ActionApprovalEnvelope` in the strict Job and require exact equality with
   the SHA-256-pinned deployment inventory before entering the execution gate.
3. Expose the deployment's existing `ActionApprovalInputAuthority` through the verified runtime and
   reuse the same instance for Capability Graph and General Attack claims.
4. Let `GeneralAttackActionExecutionGate` admit T2 only when a complete approval provider, verifier,
   and issuer binding are present. Retain its T3+ and write rejection.
5. Restrict the product profile to zero-cost, non-networked no-write Definitions that currently
   require approval: T2 or T0/T1 with `approvalRequired=true`.
6. Return the existing approval and receipt identities alongside the existing Permit and
   authenticated outcome identities.
7. Preserve terminal no-redispatch behavior for exact retry, cancellation, callback failure, and
   unknown outcome.

## Consequences

- T2 General Attack obtains one daemon-backed product path without a new approval authority or wire.
- A Job copy cannot authenticate itself; the deployment inventory and verifier remain mandatory.
- Approval-free and approved product policies remain visibly separated.
- T3+, write, cleanup, network access, generic pricing, and cross-host verifier pinning remain closed.
- The runtime dataclass exposes one additional process-local verifier reference but no serializable
  deployment field or persisted authority.

## Rejected alternatives

### Reuse `general-attack-v1` with an optional approval

Rejected because an optional field would make the product ceiling less explicit and could let
callers treat irrelevant approvals as authorization for an otherwise approval-free action.

### Trust the Job approval digest

Rejected because content addressing proves canonical integrity, not operator or issuer authority.

### Construct another General Attack approval verifier

Rejected because the existing deployment verifier already authenticates the same exact envelope.
Two verifier instances or policies could drift at the final Permit boundary.

### Advance the deployment wire

Rejected because v1alpha1/v1alpha2 already carry the complete approval inventory. Exposing the
existing verified runtime object is sufficient and avoids migration without weakening authority.

## Compatibility and rollback

The Job profile and runtime reference are additive. No persisted wire changes. Rollback disables
the profile and retains schema-v4 approval, Permit, receipt, and Run evidence for manual review.

## Related documents

- [SUP-008 contract](../orchestration/SUP-008-approved-general-attack-control-plane-profile.md)
- [APPROVAL-001A contract](../orchestration/APPROVAL-001A-single-action-approval.md)
- [ADR-0134](0134-consume-single-approval-with-action-permit.md)
- [ADR-0140](0140-expose-general-attack-through-control-plane.md)
