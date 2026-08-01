# WALK-005A: Approved Execution Candidate Admission

- Status: Implemented
- Authority contract: `pajin.dev/walking-candidate-admission/v1alpha1`
- Decision: [ADR-0072](../adr/0072-approved-permitted-walking-candidate-admission.md)

## Scope

WALK-005A is the first half of WALK-005. It admits one unconfirmed Candidate only after reopening
the WALK-004 authority and a separate sealed Capability execution Run. It does not dispatch a Tool,
create an approval, issue a Grant or Permit, run semantic validation, reproduce a Claim, confirm a
Finding, or claim remediation success.

The existing generic Candidate and deterministic Atomic Claim contracts are reused. Existing
Restricted Replay remains KISA M03/M06/A04-specific, so MCP replay is deliberately deferred to a
separate WALK-005B contract instead of being inferred from structural similarity.

## Required authority

`WalkingCandidateAdmissionRunner` requires all of the following:

- a fully re-verified sealed WALK-004 authority whose Plan is
  `request-independent-approval / proposed-not-authorized`;
- an explicit `ToolLoopApproval` bound to an exact `PendingToolIntent` and `ToolRequest`;
- a content-addressed `WalkingIndependentApprovalReceipt` that binds that approval to the exact
  WALK-004 authority, Plan, and canonical `CapabilityGrant` digest;
- exactly one copy of that receipt sealed in the execution Run before the Permit dispatch claim;
- a consumed `ActionPermit` matching the exact request and normalized parameter digests;
- a sealed Capability dispatch lifecycle reconciled as `completed`, with the same Grant digest in
  its claimed and terminal events;
- the exact Gateway evidence artifact, Policy Decision, Tool Result, Worker Result, and terminal
  Gateway outcome digest; and
- an exact Capability/Tool/target binding inherited from WALK-003.

The execution evidence must explicitly report all three bounded observables:

- the document-derived instruction-hijacking marker reached the registered MCP Tool;
- the target's independent authorization control was not enforced; and
- internal data access occurred.

These are target observations, not values synthesized from suspicious input. The bundled demo MCP
inspector does not emit the authorization or internal-data observables and therefore cannot produce
a WALK-005A Candidate by itself.

## Output authority

`WalkingCandidateAdmissionAuthority` binds the complete replan and execution authorities to one
deterministic, unvalidated A02 Candidate and its exact validity, impact, and severity Atomic Claims.
The state is fixed to `candidate-admitted-not-confirmed`. Its `candidate_production()` projection
supplies the existing validation gate with exact request-to-target-to-threat authority, but it does
not create semantic support or independent replay evidence.

The separate output Run seals `campaign.json`,
`walking-candidate-admission-authority.json`, `run.json`, and one exact publication event.
`load_walking_candidate_admission_authority` reconstructs the complete authority and audit payload.

## Negative boundaries

Admission fails closed for:

- an approval added after the dispatch claim, omitted, duplicated, expired, or bound to another
  Tool, target, method, arguments, request, Plan, or replan authority;
- a forged, unconsumed, cross-Run, or request-substituted Permit;
- an omitted, expired, cross-Campaign, wrong-subject, over-risk, target/tool-mismatched, or
  post-approval-substituted Capability Grant;
- a non-completed, denied, failed, cancelled, expired, or digest-mismatched Gateway lifecycle;
- a modified or unsealed evidence artifact;
- Campaign, target, Snapshot, Capability, Tool, risk, or schema lineage substitution;
- missing or contradictory authorization and internal-data observables; or
- caller-authored Candidate or Atomic Claim substitution.

## Compatibility, migration, and rollback

The authority, Runner, loader, and exports are additive and opt-in. The existing Capability dispatch
event gains an optional Grant digest; old events remain readable, while WALK-005A requires new
events that carry it. WALK-001 through WALK-004, A4/A5, ORCH-001/002, Graph, Gateway, Candidate,
and Atomic Claim wire shapes otherwise remain unchanged. No automatic migration occurs.

Rollback stops constructing WALK-005A Runs. Existing sealed authorities remain readable and remain
non-confirming. Removing this slice does not authorize replay or execution.

## Related documents

- [WALK-004 contract](WALK-004-observation-graph-replan.md)
- [ADR-0071](../adr/0071-evidence-bound-walking-observation-replan.md)
- [ADR-0025](../adr/0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR-0030](../adr/0030-candidate-aware-atomic-claim-validation.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
