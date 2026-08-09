# SUP-008: Approved General Attack Control Plane Profile

## Purpose

Expose the existing APPROVAL-001A single-action authority through one explicit General Attack
Control Plane profile without widening `general-attack-v1` or adding another approval, Permit,
receipt, store, deployment, or result wire.

## Product surface

`CampaignJobExecutor` recognizes `general-attack-approved-v1` only when its startup SHA-256-pinned
`CapabilityGraphWorkerDeployment` contains the exact `ActionApprovalEnvelope`. The strict Job
contains the same General Attack source lineage, Decision, and Grant as `general-attack-v1`, plus
one complete approval. The Job copy is not approval authority: it must exact-match the deployment
inventory and pass the same deployment-owned `ActionApprovalInputAuthority` used by
`capability-graph-v1`.

The executor rebuilds the Proposal and intent, resolves the deployed Envelope and durable used-call
count, and passes the exact approval, verifier, and issuer binding into
`GeneralAttackActionExecutionGate`. The gate then uses the existing APPROVAL-001A transaction to
consume the approval, unchanged GRAPH Permit, and non-reusable receipt atomically before Worker
dispatch. PERMIT-004A reloads the receipt and binds it into the authenticated outcome assessment.

## Activation ceiling

The approved profile accepts only an activated Definition that:

- is T2, or is T0/T1 with `approvalRequired=true`;
- is `none` or `read-only` with `cleanupRequired=false`;
- has `networkAccess=false`; and
- executes under a Campaign whose maximum monetary budget is exactly zero.

The executor continues to supply `costMicrousd=0`. Approval does not authorize T3+, write,
cleanup-required, networked, caller-priced, or non-zero-cost execution. A T0/T1 Definition that
does not require approval is rejected from the approved profile so an irrelevant approval cannot
be consumed or presented as stronger evidence.

## Result and retry semantics

A successful `CompletedExecution` contains the existing Permit and outcome identities plus the
durable approval and approval-receipt IDs and digests. It does not return a bearer authority.

Exact retry resolves the already-consumed tuple and fails permanently before any second Worker
call. Cancellation or callback failure after the atomic claim leaves the approval, Permit, receipt,
and terminal Run dispatch audit durable and sealed; it never restores redispatch authority.

## Fail-closed boundaries

The profile rejects admission and authority errors before Permit consumption or Worker invocation:

- a missing startup deployment, approval inventory, or deployment verifier;
- a missing, forged, stale, expired, or deployment-unpinned approval;
- cross-Campaign, cross-Run, cross-Envelope, cross-intent, cross-Decision, cross-Proposal,
  cross-release, cross-Capability, target, reservation, Permit, or issuer substitution;
- an approval supplied to `general-attack-v1` or omitted from the approved profile;
- an action that does not currently require approval;
- T3+, write, cleanup-required, networked, or non-zero-cost execution.

After an atomic claim, exact retry, cancellation, callback failure, or incomplete terminal evidence
fails closed without a second dispatch.

## Trust boundary

The digest-pinned deployment owns the approval inventory and verifier code selected at Worker
startup. The leased Job only selects an exact copy from that inventory. Issuer/verifier code pins,
Job admission, Decision actor provenance, Grant provenance, Tool/Policy/Worker selection, and
cross-host fencing remain process or deployment TCBs. Durable approval and receipt bytes do not by
themselves prove that a future process loaded the same verifier implementation.

## Compatibility and rollback

The profile is additive. Deployment v1alpha1/v1alpha2, Graph schema v4, approval, Permit, receipt,
Gateway, Run, and outcome wires remain unchanged. Rollback removes the profile while retaining all
consumed approvals, Permits, receipts, and sealed Run evidence. `general-attack-v1` remains
approval-free and T0/T1 only.

## Related documents

- [APPROVAL-001A contract](APPROVAL-001A-single-action-approval.md)
- [SUP-007A contract](SUP-007A-opt-in-general-attack-execution.md)
- [SUP-007B contract](SUP-007B-control-plane-general-attack-profile.md)
- [ADR-0141](../adr/0141-compose-approved-general-attack-profile.md)
