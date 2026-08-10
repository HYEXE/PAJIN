# ADR-0147: Bind Mode-neutral Claim Replay to Sealed Walking Evidence

- Status: Accepted
- Date: 2026-08-10

## Context

VAL-001 needs to advance a mode-neutral attack-chain coverage hypothesis only when an exact Atomic
Claim was reproduced by a fresh, independently approved Replay. PAJIN already has general
`ReplayClaimBinding` and `ClaimReplayAssessment` models and a complete WALK-005B2 vertical slice.
WALK-005B2 seals an exact validity Claim, Plan, approval receipt, fresh Run, request, Grant, Permit,
dispatch, Worker result, evidence, and non-confirming reproduction projection.

CHAIN-002 and CHAIN-005 share the same sealed WALK-003 MCP authorization predecessor used by that
Replay path. CHAIN-001, CHAIN-003, and CHAIN-004 have no corresponding executed Candidate and Replay
predecessor. Treating surface or hypothesis evidence as if it were a Replay, or adding another
execution path, would either invent evidence or duplicate existing authority.

## Decision

1. Reuse the existing WALK-005B2 `WalkingMCPClaimReplayAuthority`; do not create another Replay
   compiler, approval, Grant, Permit, dispatcher, Worker, or mutable store.
2. Register VAL-001 for CHAIN-002 and CHAIN-005 only. Both must re-verify through their existing
   compiler/verifier against the supplied sealed WALK-003 outcome.
3. Reopen and verify the WALK-005B2 Run, copied evidence, artifact, publication event, and complete
   authority through the existing loader.
4. Require the Chain and Replay to contain exactly the same `SealedMCPAuthorizationHypothesisDependency`,
   including Run root, artifact SHA-256, hypothesis ID, and hypothesis digest.
5. Bind only the exact validity `AtomicClaim` and its `REPRODUCED` projection. Candidate, Claim,
   replay Run, request, execution digest, approval receipt, Grant, Permit, dispatch, Worker, evidence,
   and publication coordinates enter one content-addressed binding digest.
6. Preserve the complete Chain and sealed WALK-005B2 dependency in the VAL-001 authority and rebuild
   both predecessors on verification.
7. Fix the result to `validity-reproduced-not-confirmed`. New execution, another Replay, confirmation,
   and Finding authority remain false.
8. Keep the contract identical for every legacy Campaign mode while retaining the exact Campaign
   and predecessor identities.

## Consequences

- CHAIN-002 and CHAIN-005 can carry verified validity-Claim reproduction without mutating their
  original `hypothesized-not-validated` artifacts.
- Cross-lineage Chain/Replay pairing, stale source publication, mutated Replay artifact, Claim or
  Chain substitution, forged binding digest, and authority-marker escalation fail closed.
- No authority store or execution path is duplicated; WALK-005B2 remains the owner of Replay
  execution evidence.
- CHAIN-001/003/004 remain unsupported rather than receiving synthetic or structurally inferred
  Replay status.
- Existing KISA and public `ClaimReplayAssessment` wire meanings remain unchanged; VAL-001 is an
  additive Chain-bound projection.

## Rejected alternatives

### Generalize all five Chains structurally

Rejected because CHAIN-001/003/004 have Surface-only predecessors and no exact executed Claim Replay.
Topology equality cannot replace observed fresh evidence.

### Compile a new Replay from the Chain

Rejected because attack-chain authorities intentionally grant no execution. WALK-005B1/B2 already
owns planning, approval, dispatch, freshness, and evidence verification.

### Treat Claim reproduction as Finding confirmation

Rejected because one reproduced validity Claim does not establish impact, severity, negative
controls, or the full confirmation gate.

### Project only IDs and digests

Rejected for the first slice because the complete embedded Chain and WALK-005B2 authority let wire
validation retain their existing code-owned invariants before external predecessor re-verification.

## Compatibility and rollback

The change is additive. Existing Chain, WALK, Replay, Claim, Validation Decision, Finding, Report,
and Control Plane artifacts keep their meanings. Rollback removes the VAL-001 contract, compiler,
verifier, tests, and exports without rewriting any predecessor Run or granting Replay status to an
unsupported Chain.

## Related documents

- [VAL-001 contract](../orchestration/VAL-001-mode-neutral-claim-replay.md)
- [WALK-005B2 contract](../orchestration/WALK-005B2-plan-bound-mcp-claim-replay.md)
- [CHAIN-002 contract](../orchestration/CHAIN-002-file-upload-rag-tool-abuse.md)
- [CHAIN-005 contract](../orchestration/CHAIN-005-mcp-authorization-privileged-action.md)
- [ADR-0036](0036-claim-bound-replay-execution-authority.md)
