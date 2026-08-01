# ADR-0072: Approved and Permitted Walking Candidate Admission

- Status: Accepted
- Date: 2026-08-01

## Context

WALK-004 deliberately ends with a non-executable approval-request Plan. PAJIN already has exact
Candidate and Atomic Claim models, sealed Tool Gateway evidence, consumed ActionPermits, and crash
reconciliation. Its implemented Restricted Replay and Retest policies, however, are intentionally
limited to exact KISA M03/M06/A04 scenarios.

Treating the WALK-004 Plan as approval, accepting an in-memory ToolResult, or relabeling an MCP
Candidate as a structurally similar KISA scenario would collapse distinct authority boundaries.
Deriving authorization failure or internal-data access solely from suspicious input would also
synthesize the conclusion that Candidate admission is supposed to prove.

## Decision

1. Split WALK-005 into an approved execution Candidate admission boundary (WALK-005A) and a later
   MCP-specific Claim-bound Restricted Replay boundary (WALK-005B).
2. Reopen and verify the complete sealed WALK-004 authority before accepting runtime evidence.
3. Require an existing explicit approval bound to the exact Tool intent, request, and canonical
   CapabilityGrant digest. Seal a content-addressed projection of it in the execution Run before
   the Permit dispatch claim.
4. Require a consumed ActionPermit and use existing Capability dispatch reconciliation to prove one
   completed sealed Permit-to-Gateway lifecycle with no redispatch inference.
5. Add an optional Grant digest to the existing dispatch event schema for backward-compatible
   readers. New Gateway dispatches record it in claimed and terminal events; WALK-005A requires it
   and rejects legacy events that do not prove the Grant actually used by Gateway.
6. Reconstruct the exact Gateway outcome from its sealed evidence and require its digest to match
   the terminal dispatch audit event.
7. Recheck the WALK-003 Capability definition, Tool binding, target, request, normalized parameters,
   approval time, Policy Decision, Worker result, and evidence identity.
8. Admit a deterministic unvalidated Candidate only when target evidence explicitly reports the
   document-derived MCP influence, lack of independent authorization enforcement, and internal-data
   access. Do not derive those observables from the input marker.
9. Reuse the existing CandidateProduction and deterministic Atomic Claim contracts. Fix the public
   state to `candidate-admitted-not-confirmed`; create no semantic verdict, ReplayOutcome,
   confirmation, report eligibility, or Retest result.

## Consequences

- WALK-004 can now feed the existing Candidate boundary without becoming executable authority.
- Late or forged approval, Grant/Permit/request substitution, incomplete dispatch, mutated evidence,
  and caller-authored Candidate or Claim substitution fail closed.
- The default demo MCP inspector remains only an instruction-marker inspector. It does not fabricate
  authorization or internal-data evidence and cannot create this Candidate by itself.
- The first Hybrid Chain is not yet closed. WALK-005B must add a true MCP Claim-bound fresh
  execution contract before report or Retest authority can be claimed.

## Compatibility and rollback

The change is additive and opt-in. Existing Capability dispatch events remain readable because the
new Grant digest field is optional, but WALK-005A requires it. Existing Campaign,
WALK-001/002/003/004, Graph, Gateway, Candidate, validation, Replay, and Retest formats otherwise
remain unchanged. Rollback removes the new composition while retaining sealed non-confirming
artifacts for audit.

## Related documents

- [WALK-005A contract](../orchestration/WALK-005-approved-execution-candidate-admission.md)
- [ADR-0071](0071-evidence-bound-walking-observation-replan.md)
- [ADR-0025](0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR-0030](0030-candidate-aware-atomic-claim-validation.md)
- [ADR-0036](0036-claim-bound-replay-execution-authority.md)
